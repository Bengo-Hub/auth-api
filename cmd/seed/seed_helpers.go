package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/apikey"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/ent/integrationconfig"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// seedPlatformAPIKey seeds the legacy platform-internal-service-key.
// Kept for backward compatibility with services not yet migrated to the App token.
func seedPlatformAPIKey(ctx context.Context, client *ent.Client, platformTenantID uuid.UUID) error {
	const keyName = "platform-internal-service-key"

	// Check if platform API key already exists
	existingCount, err := client.APIKey.Query().
		Where(
			apikey.TenantIDEQ(platformTenantID),
			apikey.ServiceEQ("platform"),
			apikey.StatusEQ(apikey.StatusActive),
		).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("check existing keys: %w", err)
	}

	if existingCount > 0 {
		log.Printf("  ✓ Platform API key already exists")
		return nil
	}

	// Generate a new API key or use one provided via env
	var plainKey, keyPrefix, keyHash string

	if envKey := os.Getenv("INTERNAL_SERVICE_KEY"); envKey != "" {
		// Use the provided key
		plainKey = envKey
		if len(plainKey) >= 8 {
			keyPrefix = plainKey[:8]
		} else {
			keyPrefix = plainKey
		}
		hashBytes := sha256.Sum256([]byte(plainKey))
		keyHash = hex.EncodeToString(hashBytes[:])
		log.Printf("  ℹ️  Using INTERNAL_SERVICE_KEY from environment")
	} else {
		// Generate a new key
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate random bytes: %w", err)
		}
		plainKey = "bng_" + base64.URLEncoding.EncodeToString(b)
		keyPrefix = plainKey[:8]
		hashBytes := sha256.Sum256([]byte(plainKey))
		keyHash = hex.EncodeToString(hashBytes[:])
	}

	_, err = client.APIKey.Create().
		SetName(keyName).
		SetKeyHash(keyHash).
		SetKeyPrefix(keyPrefix).
		SetTenantID(platformTenantID).
		SetService("platform").
		SetScopes([]string{"*"}).
		SetStatus(apikey.StatusActive).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("create platform API key: %w", err)
	}

	// Also store the plain key in integration_configs so auth-api can resolve it
	// dynamically at runtime without a pod restart (superusers rotate via auth-ui).
	// Stored as plain JSON here; the running app's integrations.Service will
	// re-encrypt it on first SaveConfig call from auth-ui.
	credsJSON, _ := json.Marshal(map[string]string{"key": plainKey})
	icExists, _ := client.IntegrationConfig.Query().
		Where(integrationconfig.Name("subscription_api_key"), integrationconfig.TenantIDIsNil()).
		Exist(ctx)
	var icErr error
	if !icExists {
		icErr = client.IntegrationConfig.Create().
			SetName("subscription_api_key").
			SetDisplayName("Subscription Service API Key").
			SetDescription("Platform API key for auth-api → subscriptions-api S2S JWT enrichment. Rotate via auth-ui without pod restart.").
			SetEncryptedCredentials(string(credsJSON)).
			SetIsActive(true).
			SetStatus("active").
			Exec(ctx)
	}
	if icErr != nil {
		// Non-fatal: app falls back to AUTH_SUBSCRIPTION_API_KEY env var
		log.Printf("  ⚠️  Could not store key in integration_configs (app will use env fallback): %v", icErr)
	} else {
		log.Printf("  ✓ Platform API key stored in integration_configs as 'subscription_api_key'")
	}

	log.Printf("  ✅ Platform API key created!")
	log.Printf("  ⚠️  IMPORTANT: Save this key — it will NOT be shown again:")
	log.Printf("  INTERNAL_SERVICE_KEY=%s", plainKey)
	log.Printf("  Set this in auth-api-secrets (and all other service secrets) as INTERNAL_SERVICE_KEY.")
	return nil
}

// seedIntegrations seeds platform-level OAuth integration configurations (social logins).
func seedIntegrations(ctx context.Context, client *ent.Client, apiBaseURL string) error {
	log.Println("Seeding platform integrations...")
	oauthApps := []struct {
		name        string
		displayName string
		description string
	}{
		{"google", "Google OAuth", "Google Social Login integration"},
		{"github", "GitHub OAuth", "GitHub Social Login integration"},
		{"microsoft", "Microsoft OAuth", "Microsoft Social Login integration"},
	}

	for _, app := range oauthApps {
		clientID := os.Getenv(fmt.Sprintf("%s_CLIENT_ID", strings.ToUpper(app.name)))
		clientSecret := os.Getenv(fmt.Sprintf("%s_CLIENT_SECRET", strings.ToUpper(app.name)))
		// GitHub: accept GIT_APP_ID / GIT_APP_SECRET as alternative env names
		if app.name == "github" {
			if clientID == "" {
				clientID = os.Getenv("GIT_APP_ID")
			}
			if clientSecret == "" {
				clientSecret = os.Getenv("GIT_APP_SECRET")
			}
		}
		// Track whether real credentials were provided before falling back to demo placeholders.
		// When hasRealCreds=false the seed must NOT overwrite an existing record — doing so
		// would destroy credentials that were configured via the admin UI.
		hasRealCreds := clientID != "" && clientSecret != ""
		if !hasRealCreds {
			clientID = fmt.Sprintf("demo_%s_client_id", app.name)
			clientSecret = fmt.Sprintf("demo_%s_client_secret", app.name)
		}

		creds := map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
		}
		if apiBaseURL != "" {
			creds["redirect_url"] = fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", strings.TrimRight(apiBaseURL, "/"), app.name)
		}
		// Microsoft: seed tenant_id for tenant-specific auth URL (default common)
		if app.name == "microsoft" {
			if t := os.Getenv("MICROSOFT_TENANT_ID"); t != "" {
				creds["tenant_id"] = t
			} else {
				creds["tenant_id"] = "common"
			}
		}

		exists, err := client.IntegrationConfig.Query().
			Where(integrationconfig.Name(app.name), integrationconfig.TenantIDIsNil()).
			Exist(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error checking integration %s: %v", app.name, err)
			continue
		}

		if exists {
			if !hasRealCreds {
				// Record already configured (via admin UI or a previous seed with real creds).
				// No env credentials supplied — skip to avoid overwriting admin-configured values.
				log.Printf("  ✓ Integration %s already configured — skipping (set %s_CLIENT_ID/SECRET env vars to update)", app.name, strings.ToUpper(app.name))
				continue
			}
			// Real credentials explicitly provided: sync them.
			credsJSON, _ := json.Marshal(creds)
			_, err = client.IntegrationConfig.Update().
				Where(integrationconfig.Name(app.name), integrationconfig.TenantIDIsNil()).
				SetEncryptedCredentials(string(credsJSON)).
				SetIsActive(true).
				SetStatus("active").
				Save(ctx)
		} else {
			credsJSON, _ := json.Marshal(creds)
			err = client.IntegrationConfig.Create().
				SetName(app.name).
				SetDisplayName(app.displayName).
				SetDescription(app.description).
				SetEncryptedCredentials(string(credsJSON)).
				SetIsActive(true).
				SetStatus("active").
				Exec(ctx)
		}
		if err != nil {
			log.Printf("  ⚠️  Error seeding integration %s: %v", app.name, err)
		} else {
			log.Printf("  ✓ Seeded integration: %s", app.name)
		}
	}
	return nil
}

// seedPlatformApp creates the default platform App with a GitHub-style bng_app_* token.
// Services can migrate to this token progressively, replacing the legacy INTERNAL_SERVICE_KEY.
// The token is stored only as a SHA-256 hash; the plain token is printed once for operator storage.
func seedPlatformApp(ctx context.Context, client *ent.Client) error {
	const appName = "Codevertex Platform Services"

	// Idempotent: skip if already exists
	exists, err := client.App.Query().
		Where(
			entapp.NameEQ(appName),
			entapp.AppTypeEQ(entapp.AppTypePlatform),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("check existing platform app: %w", err)
	}
	if exists {
		log.Printf("  ✓ Platform App already exists")
		return nil
	}

	// Generate bng_app_* token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate token bytes: %w", err)
	}
	token := "bng_app_" + base64.URLEncoding.EncodeToString(b)
	prefix := token
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	hashBytes := sha256.Sum256([]byte(token))
	keyHash := hex.EncodeToString(hashBytes[:])

	// Generate public client_id
	cidBytes := make([]byte, 6)
	if _, err := rand.Read(cidBytes); err != nil {
		return fmt.Errorf("generate client_id: %w", err)
	}
	clientID := "app_" + hex.EncodeToString(cidBytes)

	_, err = client.App.Create().
		SetName(appName).
		SetDescription("Default platform app for S2S calls across all Codevertex services").
		SetAppType(entapp.AppTypePlatform).
		SetClientID(clientID).
		SetKeyHash(keyHash).
		SetKeyPrefix(prefix).
		SetScopes([]string{"s2s:*"}).
		SetStatus(entapp.StatusActive).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("create platform app: %w", err)
	}

	log.Printf("  ✅ Platform App created! client_id=%s", clientID)
	log.Printf("  ⚠️  IMPORTANT: Save this token — it will NOT be shown again:")
	log.Printf("  PLATFORM_APP_TOKEN=%s", token)
	log.Printf("  Configure this in each service's Settings → Integrations page as the S2S auth token.")
	return nil
}

// publishSeedUserEvent writes an auth.user.* outbox record so the running auth-api
// outbox publisher picks it up and broadcasts to downstream services via NATS.
// This triggers pos-api staff profile provisioning, inventory user sync,
// logistics rider registration, etc. for all seed-created or seed-updated users.
// New users receive event_type="created"; re-runs receive "updated" to re-trigger
// provisioning without causing duplicate key errors in downstream services.
func publishSeedUserEvent(ctx context.Context, client *ent.Client, tenantID, userID uuid.UUID, data map[string]any, eventType string) {
	event := sharedevents.NewEvent(eventType, "auth.user", userID, tenantID, data)
	if slug, ok := data["tenant_slug"].(string); ok {
		event.WithTenantSlug(slug)
	}
	payload, err := event.ToJSON()
	if err != nil {
		log.Printf("  ⚠️  marshal seed event for %s: %v", userID, err)
		return
	}
	err = client.OutboxEvent.Create().
		SetTenantID(tenantID).
		SetAggregateType("auth.user").
		SetAggregateID(userID).
		SetEventType(eventType).
		SetPayload(payload).
		SetStatus(outboxevent.StatusPENDING).
		SetAttempts(0).
		Exec(ctx)
	if err != nil {
		log.Printf("  ⚠️  write outbox event auth.user.%s for %s: %v", eventType, userID, err)
	} else {
		log.Printf("    ✓ Queued auth.user.%s → outbox for user %s", eventType, userID)
	}
}

// publishSeedPINEvent queues an auth.user.pin_set outbox event so pos-api's
// auth event handler sets the POS PIN hash on the StaffMember row.
// The pin_hash is bcrypt-hashed here so pos-api can verify with bcrypt.CompareHashAndPassword.
// The raw pin is also included (internal cluster NATS only) so pos-api can pre-compute
// pin_fast_hash for O(1) terminal identify-by-PIN lookups.
// roles is included so pos-api can create the StaffMember with the correct role if it doesn't exist.
func publishSeedPINEvent(ctx context.Context, client *ent.Client, tenantID, userID uuid.UUID, pin string, roles []string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("  ⚠️  bcrypt PIN for %s: %v", userID, err)
		return
	}
	publishSeedUserEvent(ctx, client, tenantID, userID, map[string]any{
		"user_id":  userID.String(),
		"service":  "pos",
		"pin_hash": string(hash),
		"pin":      pin,
		"roles":    roles,
	}, "pin_set")
}

// backfillTenantRedirectURIs ensures every active tenant in the DB has
// /{slug}/auth/callback redirect URIs registered on all OAuth clients.
//
// The seed's seedOAuthClients only adds URIs for the hard-coded seed tenants.
// Any tenant created via the admin API or registration form after the seed ran
// gets its URIs appended at creation time via AppendTenantRedirectURIs — but
// that can fail silently (e.g. when OAuth clients didn't exist yet at that
// moment). This function is the safety net: it runs every seed and is fully
// idempotent (no-ops when URIs already present).
func backfillTenantRedirectURIs(ctx context.Context, client *ent.Client, seedSlugs map[string]bool) error {
	// Load all OAuth clients once.
	oauthClients, err := client.OAuthClient.Query().All(ctx)
	if err != nil {
		return fmt.Errorf("query oauth clients: %w", err)
	}
	if len(oauthClients) == 0 {
		return nil
	}

	// Load all active tenants from the DB — not just the seed set.
	type tenantRow struct {
		ID   interface{}
		Slug string
	}
	allTenants, err := client.Tenant.Query().All(ctx)
	if err != nil {
		return fmt.Errorf("query tenants: %w", err)
	}

	for _, t := range allTenants {
		if seedSlugs[t.Slug] {
			continue // already handled by seedOAuthClients
		}
		slug := t.Slug
		added := false
		for _, c := range oauthClients {
			// Derive the production host from the first https://*.../auth/callback URI.
			prodHost := ""
			for _, u := range c.RedirectUris {
				if strings.HasPrefix(u, "https://") && strings.HasSuffix(u, "/auth/callback") {
					trimmed := strings.TrimPrefix(u, "https://")
					prodHost = strings.SplitN(trimmed, "/", 2)[0]
					break
				}
			}
			if prodHost == "" {
				continue
			}
			prodURI := "https://" + prodHost + "/" + slug + "/auth/callback"
			localURI := "http://localhost:3000/" + slug + "/auth/callback"

			var changed bool
			uris := c.RedirectUris
			if !containsRedirectURI(uris, prodURI) {
				uris = append(uris, prodURI)
				changed = true
			}
			if !containsRedirectURI(uris, localURI) {
				uris = append(uris, localURI)
				changed = true
			}
			if !changed {
				continue
			}
			if _, err := c.Update().SetRedirectUris(uris).Save(ctx); err != nil {
				log.Printf("  ⚠️  update redirect URIs for client %s / tenant %s: %v", c.ClientID, slug, err)
				continue
			}
			// Update in-memory slice so the next non-seed tenant iteration starts
			// from the full URI list rather than the stale pre-save value.
			c.RedirectUris = uris
			added = true
		}
		if added {
			log.Printf("  ✓ Backfilled redirect URIs for tenant: %s", slug)
		}
	}
	return nil
}

func containsRedirectURI(uris []string, target string) bool {
	for _, u := range uris {
		if strings.EqualFold(strings.TrimSpace(u), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}
