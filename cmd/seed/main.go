package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/integrationconfig"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/ent/permission"
	"github.com/bengobox/auth-api/internal/ent/rolepermission"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	// Load minimal config for seeding (no OAuth validation needed)
	cfg, err := config.LoadForSeed()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	client, _, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer client.Close()

	// Ensure schema exists
	if err := database.RunMigrations(ctx, client); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	log.Println("Starting seed process...")

	// Default tenants (align with notifications-api and all SSO-integrating services).
	tenants := []struct {
		name            string
		slug            string
		baseDomain      string
		isPlatformOwner bool
	}{
		{"CodeVertex", "codevertex", "codevertexitsolutions.com", true},
		{"Masterspace Solutions", "mss", "masterspace.co.ke", false},
		{"Urban Loft Cafe", "urban-loft", "theurbanloftcafe.com", false},
		{"Kenya Urban Roads Authority (KURA)", "kura", "kura.go.ke", false},
		{"UltiChange", "ultichange", "ultichange.org", false},
	}

	var tenantEntities []*struct {
		ID   uuid.UUID
		Name string
		Slug string
	}

	for _, t := range tenants {
		meta := map[string]any{"base_domain": t.baseDomain}
		if t.isPlatformOwner {
			meta["is_platform_owner"] = true
			meta["scope"] = "platform"
		}
		tenantEntity, err := client.Tenant.Query().Where(tenant.SlugEQ(t.slug)).Only(ctx)
		if err != nil {
			tenantEntity, err = client.Tenant.Create().
				SetName(t.name).
				SetSlug(t.slug).
				SetStatus("active").
				SetMetadata(meta).
				Save(ctx)
			if err != nil {
				log.Fatalf("create tenant %s: %v", t.slug, err)
			}
			log.Printf("✓ Created tenant: %s (%s) base_domain=%s", t.name, t.slug, t.baseDomain)
		} else {
			_, _ = tenantEntity.Update().SetMetadata(meta).Save(ctx)
			log.Printf("✓ Tenant exists: %s (%s)", t.name, t.slug)
		}

		tenantEntities = append(tenantEntities, &struct {
			ID   uuid.UUID
			Name string
			Slug string
		}{
			ID:   tenantEntity.ID,
			Name: tenantEntity.Name,
			Slug: tenantEntity.Slug,
		})
	}

	hasher := password.NewHasher(cfg.Security)

	// Seed demo user with publicly safe credentials
	const (
		demoEmail    = "demo@bengobox.dev"
		demoPassword = "DemoUser2024!"
	)

	demoHash, err := hasher.Hash(demoPassword)
	if err != nil {
		log.Fatalf("hash demo password: %v", err)
	}

	demoUser, err := client.User.Create().
		SetEmail(demoEmail).
		SetPasswordHash(demoHash).
		SetStatus("active").
		SetPrimaryTenantID(tenantEntities[0].ID.String()).
		SetProfile(map[string]any{
			"name":       "Demo User",
			"is_demo":    true,
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		demoUser, err = client.User.Query().Where(user.EmailEQ(demoEmail)).Only(ctx)
		if err != nil {
			log.Fatalf("seed demo user: %v", err)
		}
		log.Printf("✓ Demo user exists: %s", demoEmail)
	} else {
		log.Printf("✓ Created demo user: %s", demoEmail)
	}

	// Add demo user membership to all tenants
	for _, tenantEnt := range tenantEntities {
		exists, err := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(demoUser.ID),
				tenantmembership.TenantID(tenantEnt.ID),
			).
			Exist(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error checking membership for %s: %v", tenantEnt.Slug, err)
			continue
		}
		if exists {
			log.Printf("  ✓ Demo membership exists for %s", tenantEnt.Slug)
			continue
		}

		_, err = client.TenantMembership.Create().
			SetUserID(demoUser.ID).
			SetTenantID(tenantEnt.ID).
			SetRoles([]string{"member"}).
			Save(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error creating demo membership for %s: %v", tenantEnt.Slug, err)
		} else {
			log.Printf("  ✓ Added demo member role in %s", tenantEnt.Slug)
		}
	}

	// Seed platform owner / default super admin
	adminEmail := os.Getenv("SEED_SUPER_ADMIN_EMAIL")
	if adminEmail == "" {
		adminEmail = os.Getenv("SEED_ADMIN_EMAIL")
	}
	if adminEmail == "" {
		adminEmail = "admin@codevertexitsolutions.com"
	}
	adminPassword := os.Getenv("SEED_SUPER_ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = os.Getenv("SEED_ADMIN_PASSWORD")
	}
	if adminPassword == "" {
		adminPassword = "ChangeMe123!"
	}

	if adminEmail != "" && adminPassword != "" {
		adminHash, err := hasher.Hash(adminPassword)
		if err != nil {
			log.Fatalf("hash admin password: %v", err)
		}

		adminUser, err := client.User.Create().
			SetEmail(adminEmail).
			SetPasswordHash(adminHash).
			SetStatus("active").
			SetPrimaryTenantID(tenantEntities[0].ID.String()).
			Save(ctx)
		if err != nil {
			adminUser, err = client.User.Query().Where(user.EmailEQ(adminEmail)).Only(ctx)
			if err != nil {
				log.Fatalf("seed admin user: %v", err)
			}
			log.Printf("✓ Admin user exists: %s", adminEmail)
		} else {
			log.Printf("✓ Created admin user: %s", adminEmail)
		}

		// Add superuser membership to all tenants
		for _, tenantEnt := range tenantEntities {
			exists, err := client.TenantMembership.Query().
				Where(
					tenantmembership.UserID(adminUser.ID),
					tenantmembership.TenantID(tenantEnt.ID),
				).
				Exist(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error checking admin membership for %s: %v", tenantEnt.Slug, err)
				continue
			}
			if exists {
				log.Printf("  ✓ Admin membership exists for %s", tenantEnt.Slug)
				continue
			}

			_, err = client.TenantMembership.Create().
				SetUserID(adminUser.ID).
				SetTenantID(tenantEnt.ID).
				SetRoles([]string{"superuser"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating admin membership for %s: %v", tenantEnt.Slug, err)
			} else {
				log.Printf("  ✓ Added superuser role in %s", tenantEnt.Slug)
			}
		}
	}

	// Seed tenant-specific admin for Urban Loft Cafe
	urbanLoftTenant := tenantEntities[2]
	tenantAdminEmail := "admin@theurbanloftcafe.com"
	tenantAdminPassword := "TenantAdmin2024!"
	tenantAdminHash, _ := hasher.Hash(tenantAdminPassword)

	tenantAdmin, err := client.User.Create().
		SetEmail(tenantAdminEmail).
		SetPasswordHash(tenantAdminHash).
		SetStatus("active").
		SetPrimaryTenantID(urbanLoftTenant.ID.String()).
		SetProfile(map[string]any{
			"name":       "Urban Loft Admin",
			"created_by": "seed",
		}).
		Save(ctx)
	if err != nil {
		tenantAdmin, err = client.User.Query().Where(user.EmailEQ(tenantAdminEmail)).Only(ctx)
		if err != nil {
			log.Printf("⚠️  seed tenant admin: %v", err)
		} else {
			log.Printf("✓ Tenant admin exists: %s", tenantAdminEmail)
		}
	} else {
		log.Printf("✓ Created tenant admin: %s", tenantAdminEmail)
	}

	if tenantAdmin != nil {
		exists, _ := client.TenantMembership.Query().
			Where(
				tenantmembership.UserID(tenantAdmin.ID),
				tenantmembership.TenantID(urbanLoftTenant.ID),
			).Exist(ctx)
		if !exists {
			_, err = client.TenantMembership.Create().
				SetUserID(tenantAdmin.ID).
				SetTenantID(urbanLoftTenant.ID).
				SetRoles([]string{"admin"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating tenant admin membership: %v", err)
			} else {
				log.Printf("  ✓ Added admin role in %s", urbanLoftTenant.Slug)
			}
		}
	}

	// Seed staff users for all tenants
	log.Println("Seeding staff users for all tenants...")
	for _, te := range tenantEntities {
		staffEmail := fmt.Sprintf("staff@%s.com", te.Slug)
		staffPassword := fmt.Sprintf("Staff%s2024!", te.Slug)
		staffHash, _ := hasher.Hash(staffPassword)

		staffUser, err := client.User.Create().
			SetEmail(staffEmail).
			SetPasswordHash(staffHash).
			SetStatus("active").
			SetPrimaryTenantID(te.ID.String()).
			SetProfile(map[string]any{
				"name":       fmt.Sprintf("%s Staff", te.Name),
				"phone":      "+254700000003",
				"created_by": "seed",
				"role":       "staff",
			}).
			Save(ctx)
		if err != nil {
			staffUser, err = client.User.Query().Where(user.EmailEQ(staffEmail)).Only(ctx)
			if err != nil {
				log.Printf("  ⚠️  seed staff for %s: %v", te.Slug, err)
			} else {
				log.Printf("  ✓ Staff exists for %s: %s", te.Slug, staffEmail)
			}
		} else {
			log.Printf("  ✓ Created staff for %s: %s", te.Slug, staffEmail)
		}

		if staffUser != nil {
			exists, _ := client.TenantMembership.Query().
				Where(
					tenantmembership.UserID(staffUser.ID),
					tenantmembership.TenantID(te.ID),
				).Exist(ctx)
			if !exists {
				_, _ = client.TenantMembership.Create().
					SetUserID(staffUser.ID).
					SetTenantID(te.ID).
					SetRoles([]string{"staff"}).
					Save(ctx)
				log.Printf("    ✓ Added staff role in %s", te.Slug)
			}
		}
	}

	// Seed permissions and role-permission mapping
	log.Println("Seeding permissions and role-permission mapping...")
	actions := []string{"add", "read", "read_own", "change", "change_own", "delete", "manage", "manage_own", "view"}
	resources := []string{"orders", "menu", "users", "tenants", "riders", "inventory", "settings", "gateways", "catalog"}
	permissionIDs := make(map[string]int)
	for _, res := range resources {
		for _, act := range actions {
			code := res + ":" + act
			perm, err := client.Permission.Query().Where(permission.CodeEQ(code)).Only(ctx)
			if err != nil {
				perm, err = client.Permission.Create().
					SetCode(code).
					SetResource(res).
					SetAction(act).
					Save(ctx)
				if err != nil {
					log.Printf("  ⚠️  Error creating permission %s: %v", code, err)
					continue
				}
				log.Printf("  ✓ Created permission: %s", code)
			}
			permissionIDs[code] = perm.ID
		}
	}

	rolePerms := map[string][]string{
		"superuser": {},
		"admin":     {},
		"staff":     {"orders:read", "orders:change", "orders:add", "menu:read", "menu:change", "menu:add", "catalog:view", "catalog:manage", "riders:read", "inventory:read", "inventory:change"},
		"member":    {"orders:read_own", "orders:change_own", "orders:add", "menu:read", "catalog:view"},
		"rider":     {"riders:read_own", "riders:change_own", "orders:read"},
	}
	for roleName, codes := range rolePerms {
		if len(codes) == 0 {
			codes = make([]string, 0, len(permissionIDs))
			for code := range permissionIDs {
				codes = append(codes, code)
			}
		}
		for _, code := range codes {
			pid, ok := permissionIDs[code]
			if !ok {
				continue
			}
			exists, _ := client.RolePermission.Query().
				Where(rolepermission.RoleNameEQ(roleName), rolepermission.PermissionIDEQ(pid)).
				Exist(ctx)
			if exists {
				continue
			}
			_, err = client.RolePermission.Create().
				SetRoleName(roleName).
				SetPermissionID(pid).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error creating role_permission %s/%s: %v", roleName, code, err)
			}
		}
		log.Printf("  ✓ Role %s: %d permissions", roleName, len(codes))
	}

	// Seed platform-level integration configurations (social logins)
	if err := seedIntegrations(ctx, client, cfg.Token.Issuer); err != nil {
		log.Printf("⚠️  Failed to seed integrations: %v", err)
	}

	// Seed OAuth Clients
	log.Println("Seeding OAuth Clients...")
	type oauthClientSpec struct {
		ID           string
		Name         string
		RedirectURIs []string
		Public       bool
	}
	var tenantSlugs []string
	for _, te := range tenantEntities {
		tenantSlugs = append(tenantSlugs, te.Slug)
	}

	notificationsRedirects := []string{
		"https://notifications.codevertexitsolutions.com/auth/callback",
		"http://localhost:3000/auth/callback",
	}
	orderingRedirects := []string{}
	subscriptionsRedirects := []string{}
	treasuryRedirects := []string{}
	posRedirects := []string{}
	inventoryRedirects := []string{}
	logisticsRedirects := []string{}
	for _, slug := range tenantSlugs {
		notificationsRedirects = append(notificationsRedirects,
			"https://notifications.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3000/"+slug+"/auth/callback",
		)
		orderingRedirects = append(orderingRedirects,
			"https://ordersapp.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3001/"+slug+"/auth/callback",
		)
		subscriptionsRedirects = append(subscriptionsRedirects,
			"https://pricing.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3010/"+slug+"/auth/callback",
		)
		treasuryRedirects = append(treasuryRedirects,
			"https://books.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3011/"+slug+"/auth/callback",
		)
		posRedirects = append(posRedirects,
			"https://pos.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3012/"+slug+"/auth/callback",
		)
		inventoryRedirects = append(inventoryRedirects,
			"https://inventory.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3015/"+slug+"/auth/callback",
		)
		logisticsRedirects = append(logisticsRedirects,
			"https://logistics.codevertexitsolutions.com/"+slug+"/auth/callback",
			"http://localhost:3013/"+slug+"/auth/callback",
		)
	}
	// Also allow non-tenant callback for subscriptions/treasury/pos/inventory/logistics when used without org in path
	subscriptionsRedirects = append(subscriptionsRedirects, "https://pricing.codevertexitsolutions.com/auth/callback", "http://localhost:3010/auth/callback")
	treasuryRedirects = append(treasuryRedirects, "https://books.codevertexitsolutions.com/auth/callback", "http://localhost:3011/auth/callback")
	posRedirects = append(posRedirects, "https://pos.codevertexitsolutions.com/auth/callback", "http://localhost:3012/auth/callback")
	inventoryRedirects = append(inventoryRedirects, "https://inventory.codevertexitsolutions.com/auth/callback", "http://localhost:3015/auth/callback")
	logisticsRedirects = append(logisticsRedirects, "https://logistics.codevertexitsolutions.com/auth/callback", "http://localhost:3013/auth/callback")

	oauthClients := []oauthClientSpec{
		{ID: "notifications-ui", Name: "BengoBox Notifications UI", RedirectURIs: notificationsRedirects, Public: true},
		{ID: "ordering-ui", Name: "BengoBox Ordering UI", RedirectURIs: orderingRedirects, Public: true},
		{ID: "rider-app", Name: "BengoBox Rider App", RedirectURIs: []string{"https://riderapp.codevertexitsolutions.com/auth/callback", "http://localhost:3002/auth/callback"}, Public: true},
		{ID: "cafe-website", Name: "Urban Loft Cafe Website", RedirectURIs: []string{"https://theurbanloftcafe.com/auth/callback", "http://localhost:3000/auth/callback"}, Public: true},
		{ID: "subscriptions-ui", Name: "BengoBox Subscriptions UI", RedirectURIs: subscriptionsRedirects, Public: true},
		{ID: "treasury-ui", Name: "BengoBox Treasury UI", RedirectURIs: treasuryRedirects, Public: true},
		{ID: "pos-ui", Name: "BengoBox POS UI", RedirectURIs: posRedirects, Public: true},
		{ID: "inventory-ui", Name: "BengoBox Inventory UI", RedirectURIs: inventoryRedirects, Public: true},
		{ID: "logistics-ui", Name: "BengoBox Logistics UI", RedirectURIs: logisticsRedirects, Public: true},
		{ID: "auth-ui", Name: "BengoBox Auth UI (Platform Admin)", RedirectURIs: []string{"https://accounts.codevertexitsolutions.com/auth/callback", "https://sso.codevertexitsolutions.com/auth/callback", "http://localhost:3014/auth/callback"}, Public: true},
	}

	for _, c := range oauthClients {
		existing, queryErr := client.OAuthClient.Query().Where(oauthclient.ClientID(c.ID)).Only(ctx)
		if queryErr != nil && !ent.IsNotFound(queryErr) {
			log.Printf("  ⚠️  Error checking client %s: %v", c.ID, queryErr)
			continue
		}

		if existing != nil {
			_, err = existing.Update().
				SetName(c.Name).
				SetRedirectUris(c.RedirectURIs).
				SetPublic(c.Public).
				SetAllowedScopes([]string{"openid", "profile", "email", "offline_access"}).
				Save(ctx)
			if err != nil {
				log.Printf("  ⚠️  Error updating client %s: %v", c.ID, err)
			} else {
				log.Printf("  ✓ Updated client: %s", c.ID)
			}
			continue
		}

		_, err = client.OAuthClient.Create().
			SetClientID(c.ID).
			SetName(c.Name).
			SetRedirectUris(c.RedirectURIs).
			SetPublic(c.Public).
			SetAllowedScopes([]string{"openid", "profile", "email", "offline_access"}).
			Save(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error creating client %s: %v", c.ID, err)
		} else {
			log.Printf("  ✓ Created client: %s", c.ID)
		}
	}

	log.Println("✅ Seeding completed successfully!")
	_ = os.Setenv("SEEDED_AT", time.Now().Format(time.RFC3339))
}

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
		if clientID == "" {
			clientID = fmt.Sprintf("demo_%s_client_id", app.name)
		}
		if clientSecret == "" {
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

		credsJSON, _ := json.Marshal(creds)

		exists, err := client.IntegrationConfig.Query().
			Where(integrationconfig.Name(app.name), integrationconfig.TenantIDIsNil()).
			Exist(ctx)
		if err != nil {
			log.Printf("  ⚠️  Error checking integration %s: %v", app.name, err)
			continue
		}

		if exists {
			_, err = client.IntegrationConfig.Update().
				Where(integrationconfig.Name(app.name), integrationconfig.TenantIDIsNil()).
				SetEncryptedCredentials(string(credsJSON)).
				SetIsActive(true).
				SetStatus("active").
				Save(ctx)
		} else {
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
