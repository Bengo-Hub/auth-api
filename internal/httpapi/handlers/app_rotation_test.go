package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/token"
)

// ─── Pure tests (no DB) ───────────────────────────────────────────────────────

func TestCredentialPrefixByEnvironment(t *testing.T) {
	sandbox := &ent.App{AppType: entapp.AppTypeTenant, Environment: entapp.EnvironmentSandbox}
	production := &ent.App{AppType: entapp.AppTypeTenant, Environment: entapp.EnvironmentProduction}
	platform := &ent.App{AppType: entapp.AppTypePlatform, Environment: entapp.EnvironmentSandbox}
	if credentialIsLive(sandbox) || !credentialIsLive(production) || !credentialIsLive(platform) || credentialIsLive(nil) {
		t.Fatal("credentialIsLive gave a wrong answer")
	}

	for _, tc := range []struct {
		live                bool
		secretPfx, tokenPfx string
	}{
		{false, "bng_cs_test_", "bng_app_test_"},
		{true, "bng_cs_live_", "bng_app_live_"},
	} {
		secret, hash, err := generateConsumerSecret(tc.live)
		if err != nil || !strings.HasPrefix(secret, tc.secretPfx) || hash != hashAPIKey(secret) {
			t.Fatalf("generateConsumerSecret(%v) = %q, %v", tc.live, secret, err)
		}
		tok, prefix, tokHash, err := generateAppToken(tc.live)
		if err != nil || !strings.HasPrefix(tok, tc.tokenPfx) || tokHash != hashAPIKey(tok) {
			t.Fatalf("generateAppToken(%v) = %q, %v", tc.live, tok, err)
		}
		if len(prefix) != keyPrefixLen || !strings.HasPrefix(tok, prefix) {
			t.Fatalf("key prefix %q is not the first %d characters of %q", prefix, keyPrefixLen, tok)
		}
	}
}

func TestPreviousCredentialMetadata(t *testing.T) {
	now := time.Now()
	secret, hash, _ := generateConsumerSecret(false)
	base := map[string]any{"note": "kept"}

	meta := withPreviousCredential(base, metaPreviousClientSecret, &previousCredential{Hash: hash, ExpiresAt: now.Add(time.Hour)})
	if _, changed := base[metaPreviousClientSecret]; changed {
		t.Fatal("withPreviousCredential changed the map it was given")
	}
	if meta["note"] != "kept" {
		t.Fatal("other metadata keys must survive")
	}
	// Round trip through JSON, as the database does.
	b, _ := json.Marshal(meta)
	var stored map[string]any
	_ = json.Unmarshal(b, &stored)

	if !previousSecretMatches(stored, secret, now) {
		t.Fatal("previous secret inside its grace period must match")
	}
	if previousSecretMatches(stored, secret+"x", now) {
		t.Fatal("a different secret must not match")
	}
	if previousSecretMatches(stored, secret, now.Add(2*time.Hour)) {
		t.Fatal("previous secret after its grace period must not match")
	}
	if previousSecretMatches(nil, secret, now) {
		t.Fatal("no metadata, no match")
	}
	cleared := withPreviousCredential(stored, metaPreviousClientSecret, nil)
	if _, ok := previousCredentialFrom(cleared, metaPreviousClientSecret); ok {
		t.Fatal("a nil credential must remove the entry")
	}
}

func TestParseRotationGrace(t *testing.T) {
	h := &AppHandler{}
	req := func(body string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	}
	if g, err := h.parseRotationGrace(req("")); err != nil || g != defaultRotationGrace {
		t.Fatalf("unconfigured default = %v %v, want %v", g, err, defaultRotationGrace)
	}
	h.SetRotationGrace(2*time.Hour, 168*time.Hour)
	cases := []struct {
		body    string
		want    time.Duration
		wantErr bool
	}{
		{"", 2 * time.Hour, false},
		{"{}", 2 * time.Hour, false},
		{`{"grace_hours":0}`, 0, false},
		{`{"grace_hours":24}`, 24 * time.Hour, false},
		{`{"grace_hours":0.5}`, 30 * time.Minute, false},
		{`{"grace_hours":168}`, 168 * time.Hour, false},
		{`{"grace_hours":169}`, 0, true},
		{`{"grace_hours":-1}`, 0, true},
		{`{"grace":1}`, 0, true},
	}
	for _, tc := range cases {
		g, err := h.parseRotationGrace(req(tc.body))
		if (err != nil) != tc.wantErr || (!tc.wantErr && g != tc.want) {
			t.Errorf("parseRotationGrace(%s) = %v, %v; want %v (error %v)", tc.body, g, err, tc.want, tc.wantErr)
		}
	}
	h.SetRotationGrace(0, 168*time.Hour)
	if g, _ := h.parseRotationGrace(req("")); g != 0 {
		t.Fatalf("a configured zero default must mean immediate, got %v", g)
	}
}

// ─── Database tests ───────────────────────────────────────────────────────────

// newGrantTestHandler builds an OIDCHandler that can mint client_credentials tokens.
func newGrantTestHandler(t *testing.T, client *ent.Client) *OIDCHandler {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	privPath, pubPath := filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	_ = os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	_ = os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600)
	tcfg := config.TokenConfig{Issuer: "https://auth.test", Audience: "codevertex", PrivateKeyPath: privPath, PublicKeyPath: pubPath,
		AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour, ClientCredentialsAudience: "codevertex-api", ClientCredentialsTTL: 15 * time.Minute}
	tokens, err := token.NewService(tcfg)
	if err != nil {
		t.Fatalf("token service: %v", err)
	}
	return &OIDCHandler{cfg: &config.Config{Token: tcfg}, tokenSvc: tokens, apps: client, logger: zap.NewNop()}
}

// captureAnnouncements records every apikey.changed payload until the test ends.
func captureAnnouncements(t *testing.T) *[]string {
	t.Helper()
	var got []string
	orig := publishKeyChanged
	publishKeyChanged = func(_, payload string) { got = append(got, payload) }
	t.Cleanup(func() { publishKeyChanged = orig })
	return &got
}

type rotationResponse struct {
	Token                         string `json:"token"`
	ClientSecret                  string `json:"client_secret"`
	KeyPrefix                     string `json:"key_prefix"`
	PreviousClientSecretExpiresAt string `json:"previous_client_secret_expires_at"`
	PreviousKeyExpiresAt          string `json:"previous_key_expires_at"`
	PreviousKeyPrefix             string `json:"previous_key_prefix"`
}

func rotate(t *testing.T, fn http.HandlerFunc, appID uuid.UUID, claims *token.Claims, body string, wantStatus int) rotationResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	fn(rec, draftRequest(http.MethodPost, body, claims, map[string]string{"id": appID.String()}))
	if rec.Code != wantStatus {
		t.Fatalf("rotate %s: status %d, want %d (%s)", body, rec.Code, wantStatus, rec.Body.String())
	}
	var out rotationResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// expirePrevious moves the grace entry's end into the past, as if the grace period ran out.
func expirePrevious(t *testing.T, client *ent.Client, id uuid.UUID, key string) {
	t.Helper()
	ctx := context.Background()
	a := client.App.GetX(ctx, id)
	p, ok := previousCredentialFrom(a.Metadata, key)
	if !ok {
		t.Fatalf("no %s entry to expire", key)
	}
	p.ExpiresAt = time.Now().Add(-time.Minute)
	client.App.UpdateOneID(id).SetMetadata(withPreviousCredential(a.Metadata, key, &p)).ExecX(ctx)
}

func TestConsumerSecretRotationGrace(t *testing.T) {
	client := newLegalTestClient(t)
	ctx := context.Background()
	h := newGrantTestHandler(t, client)
	apps := NewAppHandler(client, zap.NewNop())
	apps.SetRotationGrace(24*time.Hour, 168*time.Hour)
	announced := captureAnnouncements(t)

	sfx := uuid.NewString()[:8]
	tn := client.Tenant.Create().SetName("Dev").SetSlug("dev-rot-" + sfx).SetStatus("active").SaveX(ctx)
	first, firstHash, _ := generateConsumerSecret(false)
	_, _, keyHash, _ := generateAppToken(false)
	a := client.App.Create().SetName("Sandbox").SetAppType(entapp.AppTypeTenant).SetTenantID(tn.ID).
		SetClientID("app_rot_" + sfx).SetKeyHash(keyHash).SetKeyPrefix("bng_app_test_x").
		SetClientSecretHash(firstHash).SetScopes([]string{"etims:read"}).SaveX(ctx)
	dev := &token.Claims{TenantID: tn.ID.String(), Roles: []string{"developer"}}

	grant := func(secret string) int {
		form := url.Values{"grant_type": {"client_credentials"}}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(a.ClientID, secret)
		rec := httptest.NewRecorder()
		h.Token(rec, r)
		return rec.Code
	}

	// A grace period above the configured maximum is refused.
	rotate(t, apps.RotateSecret, a.ID, dev, `{"grace_hours":500}`, http.StatusBadRequest)

	// Default rotation: 24 hours of grace, a test-marked secret, no broadcast.
	out := rotate(t, apps.RotateSecret, a.ID, dev, "", http.StatusOK)
	second := out.ClientSecret
	if !strings.HasPrefix(second, "bng_cs_test_") {
		t.Fatalf("sandbox secret %q lacks bng_cs_test_", second)
	}
	ends, err := time.Parse(time.RFC3339, out.PreviousClientSecretExpiresAt)
	if err != nil || ends.Sub(time.Now()) < 23*time.Hour || ends.Sub(time.Now()) > 25*time.Hour {
		t.Fatalf("previous_client_secret_expires_at = %q, want about 24 hours ahead", out.PreviousClientSecretExpiresAt)
	}
	if len(*announced) != 0 {
		t.Fatalf("a rotation with grace must not cut issued tokens, announced %v", *announced)
	}
	if code := grant(first); code != http.StatusOK {
		t.Fatalf("previous secret during grace: status %d, want 200", code)
	}
	if code := grant(second); code != http.StatusOK {
		t.Fatalf("new secret: status %d, want 200", code)
	}

	// Once the grace period ends the previous secret is refused.
	expirePrevious(t, client, a.ID, metaPreviousClientSecret)
	if code := grant(first); code != http.StatusUnauthorized {
		t.Fatalf("previous secret after grace: status %d, want 401", code)
	}
	if code := grant(second); code != http.StatusOK {
		t.Fatalf("new secret after grace: status %d, want 200", code)
	}

	// Immediate rotation: the replaced secret stops at once and issued tokens are cut.
	out = rotate(t, apps.RotateSecret, a.ID, dev, `{"grace_hours":0}`, http.StatusOK)
	third := out.ClientSecret
	if out.PreviousClientSecretExpiresAt != "" {
		t.Fatal("immediate rotation must not report a previous secret")
	}
	if !slices.Contains(*announced, ClientChangedPrefix+a.ClientID) {
		t.Fatalf("immediate rotation must announce %s, got %v", ClientChangedPrefix+a.ClientID, *announced)
	}
	if code := grant(second); code != http.StatusUnauthorized {
		t.Fatalf("replaced secret after immediate rotation: status %d, want 401", code)
	}
	if code := grant(third); code != http.StatusOK {
		t.Fatalf("newest secret: status %d, want 200", code)
	}

	// Rotating twice within a grace period keeps only the most recent previous secret.
	fourth := rotate(t, apps.RotateSecret, a.ID, dev, `{"grace_hours":1}`, http.StatusOK).ClientSecret
	fifth := rotate(t, apps.RotateSecret, a.ID, dev, `{"grace_hours":1}`, http.StatusOK).ClientSecret
	if grant(third) != http.StatusUnauthorized || grant(fourth) != http.StatusOK || grant(fifth) != http.StatusOK {
		t.Fatal("only the latest replaced secret may stay in grace")
	}

	// A production app gets a live-marked secret.
	client.App.UpdateOneID(a.ID).SetEnvironment(entapp.EnvironmentProduction).ExecX(ctx)
	live := rotate(t, apps.RotateSecret, a.ID, dev, "", http.StatusOK).ClientSecret
	if !strings.HasPrefix(live, "bng_cs_live_") {
		t.Fatalf("production secret %q lacks bng_cs_live_", live)
	}
}

func TestAPIKeyRotationGrace(t *testing.T) {
	client := newLegalTestClient(t)
	ctx := context.Background()
	apps := NewAppHandler(client, zap.NewNop())
	apps.SetRotationGrace(24*time.Hour, 168*time.Hour)
	keys := NewAPIKeyHandler(client, zap.NewNop())
	announced := captureAnnouncements(t)

	sfx := uuid.NewString()[:8]
	tn := client.Tenant.Create().SetName("Dev").SetSlug("dev-key-" + sfx).SetStatus("active").SaveX(ctx)
	first, firstPrefix, firstHash, _ := generateAppToken(false)
	a := client.App.Create().SetName("Sandbox").SetAppType(entapp.AppTypeTenant).SetTenantID(tn.ID).
		SetClientID("app_key_" + sfx).SetKeyHash(firstHash).SetKeyPrefix(firstPrefix).
		SetScopes([]string{"etims:read"}).SaveX(ctx)
	dev := &token.Claims{TenantID: tn.ID.String(), Roles: []string{"developer"}}

	valid := func(key string) bool {
		resp, _, _, _, err := keys.ResolveAppToken(ctx, nil, key)
		return err == nil && resp != nil && resp.ClientID == a.ClientID
	}

	// Default rotation keeps the old key working and announces nothing.
	out := rotate(t, apps.RotateToken, a.ID, dev, "", http.StatusOK)
	second := out.Token
	if !strings.HasPrefix(second, "bng_app_test_") {
		t.Fatalf("sandbox key %q lacks bng_app_test_", second)
	}
	if out.PreviousKeyExpiresAt == "" || out.PreviousKeyPrefix != firstPrefix {
		t.Fatalf("response must show the previous key and when it stops, got %+v", out)
	}
	if len(*announced) != 0 {
		t.Fatalf("a key in grace must not be announced, got %v", *announced)
	}
	if !valid(first) || !valid(second) {
		t.Fatal("both the previous key (in grace) and the new key must validate")
	}

	// A second rotation in the grace period ends the first key now and announces it.
	third := rotate(t, apps.RotateToken, a.ID, dev, `{"grace_hours":1}`, http.StatusOK).Token
	if valid(first) {
		t.Fatal("the first key must stop once a newer rotation replaces its grace entry")
	}
	if !slices.Contains(*announced, firstHash) {
		t.Fatalf("the stopped key's hash must be announced, got %v", *announced)
	}
	if !valid(second) || !valid(third) {
		t.Fatal("the second key (in grace) and the third key must validate")
	}

	// After the grace period the previous key is refused.
	expirePrevious(t, client, a.ID, metaPreviousKey)
	if valid(second) {
		t.Fatal("previous key after grace must be refused")
	}
	if !valid(third) {
		t.Fatal("current key must still validate")
	}

	// Immediate rotation stops the replaced key and announces its hash.
	*announced = nil
	fourth := rotate(t, apps.RotateToken, a.ID, dev, `{"grace_hours":0}`, http.StatusOK).Token
	if valid(third) || !valid(fourth) {
		t.Fatal("immediate rotation must stop the replaced key at once")
	}
	if !slices.Contains(*announced, hashAPIKey(third)) {
		t.Fatalf("immediate rotation must announce the replaced key's hash, got %v", *announced)
	}

	// The fleet's internal service key is a platform app: live-marked, and its previous key
	// keeps passing the internal check during the grace period.
	oldInternal, oldPrefix, oldHash, _ := generateAppToken(true)
	p := client.App.Create().SetName("Internal").SetAppType(entapp.AppTypePlatform).
		SetClientID("app_int_" + sfx).SetKeyHash(oldHash).SetKeyPrefix(oldPrefix).
		SetScopes([]string{InternalServiceKeyScope}).SaveX(ctx)
	owner := &token.Claims{IsPlatformOwner: true}
	newInternal := rotate(t, apps.RotateToken, p.ID, owner, "", http.StatusOK).Token
	if !strings.HasPrefix(newInternal, "bng_app_live_") {
		t.Fatalf("platform key %q lacks bng_app_live_", newInternal)
	}
	if !apps.IsValidInternalServiceToken(ctx, oldInternal) || !apps.IsValidInternalServiceToken(ctx, newInternal) {
		t.Fatal("old internal key (in grace) and new internal key must both pass")
	}
	expirePrevious(t, client, p.ID, metaPreviousKey)
	if apps.IsValidInternalServiceToken(ctx, oldInternal) {
		t.Fatal("old internal key after grace must fail")
	}
}
