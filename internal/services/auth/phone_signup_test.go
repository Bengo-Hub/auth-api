package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/enttest"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/userphone"
	"github.com/bengobox/auth-api/internal/services/access"
	"github.com/bengobox/auth-api/internal/token"
)

func TestTenantPhoneSignupPolicy(t *testing.T) {
	cases := []struct {
		name     string
		meta     map[string]any
		on       bool
		role     string
		services []string
	}{
		{"no metadata", nil, false, "", nil},
		{"flag off", map[string]any{"phone_self_signup": false, "self_signup_role": "customer"}, false, "", nil},
		{"flag as string is not on", map[string]any{"phone_self_signup": "true"}, false, "", nil},
		{"on with defaults", map[string]any{"phone_self_signup": true}, true, "customer", nil},
		{"on with services from JSON", map[string]any{"phone_self_signup": true, "self_signup_services": []any{" Hadia ", 7, ""}}, true, "customer", []string{"hadia"}},
		{"staff role never honoured", map[string]any{"phone_self_signup": true, "self_signup_role": "admin"}, true, "customer", nil},
		{"another self-service role", map[string]any{"phone_self_signup": true, "self_signup_role": "student"}, true, "student", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, on := TenantPhoneSignupPolicy(&ent.Tenant{Metadata: c.meta})
			if on != c.on || p.Role != c.role || strings.Join(p.Services, ",") != strings.Join(c.services, ",") {
				t.Fatalf("got %+v %v, want role %q services %v on %v", p, on, c.role, c.services, c.on)
			}
		})
	}
}

// newPhoneSignupTestService opens an isolated Postgres schema and a Service able to issue real
// tokens (throwaway RSA key). Skips when Postgres is unreachable.
func newPhoneSignupTestService(t *testing.T) (*Service, *ent.Client, *token.Service) {
	t.Helper()
	base := os.Getenv("TEST_POSTGRES_URL")
	if base == "" {
		base = "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable"
	}
	db, err := sql.Open("postgres", base)
	if err != nil {
		t.Skipf("postgres: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("postgres unreachable: %v", err)
	}
	const schema = "ent_test_phone_signup"
	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE; CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_ = db.Close()
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	client := enttest.Open(t, "postgres", base+sep+"search_path="+schema)
	t.Cleanup(func() {
		_ = client.Close()
		if d, err := sql.Open("postgres", base); err == nil {
			_, _ = d.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE")
			_ = d.Close()
		}
	})

	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	privPath, pubPath := filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	_ = os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	_ = os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600)
	tcfg := config.TokenConfig{Issuer: "test", Audience: "test", PrivateKeyPath: privPath, PublicKeyPath: pubPath,
		AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour}
	tokens, err := token.NewService(tcfg)
	if err != nil {
		t.Fatalf("token service: %v", err)
	}
	cfg := &config.Config{Token: tcfg}
	s := New(Dependencies{EntClient: client, TokenSvc: tokens, Config: cfg, Logger: zap.NewNop()})
	// No subscription client: every tenant counts as not gated by a plan, so the member's
	// assigned services pass through to the claim unchanged.
	s.SetAccessResolver(access.New(client, nil))
	return s, client, tokens
}

func TestPhoneSelfSignup(t *testing.T) {
	s, client, tokens := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]

	newTenant := func(name string, meta map[string]any) *ent.Tenant {
		tn, err := client.Tenant.Create().SetName(name).SetSlug(name + "-" + suffix).SetStatus("active").SetMetadata(meta).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return tn
	}
	optIn := newTenant("hadia", map[string]any{
		"phone_self_signup": true, "self_signup_role": "customer", "self_signup_services": []any{"hadia"},
	})
	closed := newTenant("estate", map[string]any{})

	newUser := func(email, phone string, verified bool) *ent.User {
		u, err := client.User.Create().SetEmail(email).SetStatus("active").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.UserPhone.Create().SetUserID(u.ID).SetPhone(phone).SetIsPrimary(true).SetIsVerified(verified).Save(ctx); err != nil {
			t.Fatal(err)
		}
		return u
	}

	t.Run("unknown phone in an opted-in tenant signs up and gets tokens with the hadia service", func(t *testing.T) {
		phone := "+254711000001"
		target, err := s.FindPhoneLoginTarget(ctx, optIn.Slug, phone)
		if err != nil || target.Signup == nil || target.User != nil {
			t.Fatalf("target: %+v %v", target, err)
		}
		// Asking for a code creates nothing.
		if n, _ := client.User.Query().Count(ctx); n != 0 {
			t.Fatalf("users before verify: %d", n)
		}
		res, err := s.LoginWithPhoneOTP(ctx, target, "hadia-ui", "127.0.0.1", "test")
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if res.AccessToken == "" || res.RefreshToken == "" {
			t.Fatal("no tokens issued")
		}
		claims, err := tokens.Parse(res.AccessToken)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if strings.Join(claims.UserServices, ",") != "hadia" {
			t.Fatalf("user_services = %v, want [hadia]", claims.UserServices)
		}
		up, err := client.UserPhone.Query().Where(userphone.PhoneEQ(phone)).WithUser().Only(ctx)
		if err != nil || !up.IsVerified || !up.IsPrimary {
			t.Fatalf("phone row: %+v %v", up, err)
		}
		if !isPlaceholderEmail(up.Edges.User.Email) {
			t.Fatalf("email %q should be a placeholder", up.Edges.User.Email)
		}
		m, err := client.TenantMembership.Query().
			Where(tenantmembership.UserID(up.UserID), tenantmembership.TenantID(optIn.ID)).Only(ctx)
		if err != nil || strings.Join(m.Roles, ",") != "customer" || strings.Join(m.Services, ",") != "hadia" || m.Status != "active" {
			t.Fatalf("membership: %+v %v", m, err)
		}
		// The second sign-in is a plain member sign-in.
		again, err := s.FindPhoneLoginTarget(ctx, optIn.Slug, phone)
		if err != nil || again.Signup != nil || again.User == nil || again.User.ID != up.UserID {
			t.Fatalf("second sign-in target: %+v %v", again, err)
		}
	})

	t.Run("unknown phone without the opt-in is refused with the neutral error", func(t *testing.T) {
		if _, err := s.FindPhoneLoginTarget(ctx, closed.Slug, "+254711000002"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("existing member is unaffected", func(t *testing.T) {
		u := newUser("owner-"+suffix+"@mail.test", "+254711000003", false)
		if _, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(optIn.ID).SetRoles([]string{"hadia_support"}).SetStatus("active").Save(ctx); err != nil {
			t.Fatal(err)
		}
		target, err := s.FindPhoneLoginTarget(ctx, optIn.Slug, "+254711000003")
		if err != nil || target.Signup != nil || target.User.ID != u.ID {
			t.Fatalf("target: %+v %v", target, err)
		}
		if _, err := s.LoginWithPhoneOTP(ctx, target, "hadia-ui", "", ""); err != nil {
			t.Fatal(err)
		}
		m, _ := client.TenantMembership.Query().Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(optIn.ID)).Only(ctx)
		if strings.Join(m.Roles, ",") != "hadia_support" || m.Services != nil {
			t.Fatalf("membership changed: %+v", m)
		}
	})

	t.Run("verified phone from another tenant joins, unverified does not", func(t *testing.T) {
		verified := newUser("shopper-"+suffix+"@mail.test", "+254711000004", true)
		target, err := s.FindPhoneLoginTarget(ctx, optIn.Slug, "+254711000004")
		if err != nil || target.Signup == nil || target.User == nil || target.User.ID != verified.ID {
			t.Fatalf("join target: %+v %v", target, err)
		}
		if _, err := s.LoginWithPhoneOTP(ctx, target, "hadia-ui", "", ""); err != nil {
			t.Fatal(err)
		}
		if ok, _ := client.TenantMembership.Query().Where(tenantmembership.UserID(verified.ID), tenantmembership.TenantID(optIn.ID)).Exist(ctx); !ok {
			t.Fatal("no membership after join")
		}
		newUser("other-"+suffix+"@mail.test", "+254711000005", false)
		if _, err := s.FindPhoneLoginTarget(ctx, optIn.Slug, "+254711000005"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("unverified phone: got %v", err)
		}
	})

	t.Run("suspended member is never re-activated", func(t *testing.T) {
		u := newUser("gone-"+suffix+"@mail.test", "+254711000006", true)
		if _, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(optIn.ID).SetRoles([]string{"customer"}).SetStatus("suspended").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := s.FindPhoneLoginTarget(ctx, optIn.Slug, "+254711000006"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v", err)
		}
	})
}
