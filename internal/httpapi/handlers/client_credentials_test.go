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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/config"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/token"
)

func TestNormalizeTenantScopes(t *testing.T) {
	cases := []struct {
		in, want []string
	}{
		{[]string{"etims:write"}, []string{"etims:read", "etims:write"}},
		{[]string{"etims:read", "etims:write"}, []string{"etims:read", "etims:write"}},
		{[]string{"etims:read"}, []string{"etims:read"}},
		{[]string{" etims:write ", "etims:write"}, []string{"etims:read", "etims:write"}},
		{nil, nil},
	}
	for _, tc := range cases {
		if got := normalizeTenantScopes(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("normalizeTenantScopes(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAddedScopes(t *testing.T) {
	got := addedScopes([]string{"etims:read"}, []string{"etims:read", "etims:write"})
	if !reflect.DeepEqual(got, []string{"etims:write"}) {
		t.Fatalf("addedScopes = %v", got)
	}
	if got := addedScopes([]string{"etims:read", "etims:write"}, []string{"etims:read"}); len(got) != 0 {
		t.Fatalf("dropping a scope is not an addition, got %v", got)
	}
}

func TestGrantedScopes(t *testing.T) {
	app := []string{"etims:read", "etims:write"}
	if got, ok := grantedScopes(app, ""); !ok || !reflect.DeepEqual(got, app) {
		t.Fatalf("empty request should grant all, got %v %v", got, ok)
	}
	if got, ok := grantedScopes(app, "etims:read etims:read"); !ok || !reflect.DeepEqual(got, []string{"etims:read"}) {
		t.Fatalf("subset request, got %v %v", got, ok)
	}
	if _, ok := grantedScopes(app, "etims:read treasury:write"); ok {
		t.Fatal("a scope the app lacks must fail the request")
	}
}

func TestIPAllowedAndSecretMatches(t *testing.T) {
	if !ipAllowed(nil, "1.2.3.4") || !ipAllowed([]string{"*"}, "1.2.3.4") || !ipAllowed([]string{"1.2.3.4"}, "1.2.3.4") {
		t.Fatal("expected allowed")
	}
	if ipAllowed([]string{"5.6.7.8"}, "1.2.3.4") {
		t.Fatal("expected refused")
	}
	secret, hash, err := generateConsumerSecret()
	if err != nil || !strings.HasPrefix(secret, consumerSecretPrefix) {
		t.Fatalf("generateConsumerSecret: %q %v", secret, err)
	}
	if !secretMatches(&hash, secret) || secretMatches(&hash, secret+"x") || secretMatches(nil, secret) {
		t.Fatal("secretMatches gave a wrong answer")
	}
}

func TestAllowlistIPTrustsForwardedOnlyWithServiceKey(t *testing.T) {
	h := &APIKeyHandler{internalKey: "s2s-test-key"}
	r := httptest.NewRequest(http.MethodGet, "/validate", nil)
	r.RemoteAddr = "10.0.0.9:5555"
	r.Header.Set(HeaderOriginalClientIP, "41.90.1.2")
	if got := h.allowlistIP(r); got == "41.90.1.2" {
		t.Fatal("forwarded IP trusted without the service key")
	}
	r.Header.Set(HeaderInternalServiceKey, "wrong")
	if got := h.allowlistIP(r); got == "41.90.1.2" {
		t.Fatal("forwarded IP trusted with a wrong service key")
	}
	r.Header.Set(HeaderInternalServiceKey, "s2s-test-key")
	if got := h.allowlistIP(r); got != "41.90.1.2" {
		t.Fatalf("forwarded IP not used with a valid service key, got %q", got)
	}
}

// TestClientCredentialsGrant runs the grant end to end against a disposable Postgres schema.
func TestClientCredentialsGrant(t *testing.T) {
	client := newLegalTestClient(t)
	ctx := context.Background()

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
	h := &OIDCHandler{cfg: &config.Config{Token: tcfg}, tokenSvc: tokens, apps: client, logger: zap.NewNop()}

	sfx := uuid.NewString()[:8]
	tn := client.Tenant.Create().SetName("Dev").SetSlug("dev-" + sfx).SetStatus("active").SaveX(ctx)
	secret, secretHash, _ := generateConsumerSecret()
	_, _, keyHash, _ := generateAppToken()
	a := client.App.Create().SetName("Sandbox").SetAppType(entapp.AppTypeTenant).SetTenantID(tn.ID).
		SetClientID("app_" + sfx).SetKeyHash(keyHash).SetKeyPrefix("bng_app_x").
		SetClientSecretHash(secretHash).SetScopes([]string{"etims:read", "etims:write"}).SaveX(ctx)

	call := func(form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basicID != "" {
			r.SetBasicAuth(basicID, basicSecret)
		}
		rec := httptest.NewRecorder()
		h.Token(rec, r)
		return rec
	}

	// Wrong secret.
	if rec := call(url.Values{"grant_type": {"client_credentials"}}, a.ClientID, "bng_cs_wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: status %d, want 401", rec.Code)
	}
	// Scope beyond the app.
	if rec := call(url.Values{"grant_type": {"client_credentials"}, "scope": {"treasury:write"}}, a.ClientID, secret); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: status %d, want 400", rec.Code)
	}

	// Success with client_secret_post and a narrowed scope.
	rec := call(url.Values{"grant_type": {"client_credentials"}, "client_id": {a.ClientID}, "client_secret": {secret}, "scope": {"etims:read"}}, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("grant: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response must be no-store")
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.TokenType != "Bearer" || body.ExpiresIn != 900 || body.Scope != "etims:read" {
		t.Fatalf("unexpected body %+v", body)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(body.AccessToken, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	aud, _ := claims.GetAudience()
	if len(aud) != 1 || aud[0] != "codevertex-api" {
		t.Fatalf("audience = %v, want only codevertex-api", aud)
	}
	if claims["token_use"] != TokenUseClientCredentials || claims["tenant_id"] != tn.ID.String() ||
		claims["env"] != "sandbox" || claims["sub"] != a.ClientID {
		t.Fatalf("unexpected claims %v", claims)
	}
	if sc, _ := claims["scope"].([]any); len(sc) != 1 || sc[0] != "etims:read" {
		t.Fatalf("scope claim = %v, want [etims:read]", claims["scope"])
	}
	if _, has := claims["roles"]; has {
		t.Fatal("a client_credentials token must not carry roles")
	}

	// A suspended app gets no token.
	client.App.UpdateOneID(a.ID).SetStatus(entapp.StatusSuspended).ExecX(ctx)
	if rec := call(url.Values{"grant_type": {"client_credentials"}}, a.ClientID, secret); rec.Code != http.StatusBadRequest {
		t.Fatalf("suspended app: status %d, want 400", rec.Code)
	}
}
