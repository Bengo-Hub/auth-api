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
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/audit"
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
	cfg.Security.OAuthStateSecret = "test-state-secret-0123456789abcdef"
	s := New(Dependencies{EntClient: client, TokenSvc: tokens, Config: cfg, Logger: zap.NewNop(),
		Auditor: audit.New(client, zap.NewNop())})
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

// Review M1: anyone can attach any number to their account without proof. Such a row (never
// verified, never primary) must not lock the real holder out: the holder who proves the number
// signs up and the unproven row goes in the same transaction. A primary row stays.
func TestPhoneSelfSignupClaimsUnprovenPhone(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	tn, err := client.Tenant.Create().SetName("hadia").SetSlug("hadia-" + suffix).SetStatus("active").
		SetMetadata(map[string]any{"phone_self_signup": true, "self_signup_services": []any{"hadia"}}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	squatter, _ := client.User.Create().SetEmail("squat-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	const phone = "+254722000001"
	if _, err := s.AddUserPhone(ctx, squatter.ID, phone); err != nil {
		t.Fatal(err)
	}
	target, err := s.FindPhoneLoginTarget(ctx, tn.Slug, phone)
	if err != nil || target.Signup == nil || target.User != nil || target.ClaimPhoneID == nil {
		t.Fatalf("claim target: %+v %v", target, err)
	}
	res, err := s.LoginWithPhoneOTP(ctx, target, "hadia-ui", "", "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	up, err := client.UserPhone.Query().Where(userphone.PhoneEQ(phone)).Only(ctx)
	if err != nil || up.UserID != res.User.ID || up.UserID == squatter.ID || !up.IsVerified {
		t.Fatalf("phone row after claim: %+v %v", up, err)
	}

	// A primary row is the account's own sign-in number: never claimed.
	owner, _ := client.User.Create().SetEmail("primary-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	if _, err := client.UserPhone.Create().SetUserID(owner.ID).SetPhone("+254722000002").SetIsPrimary(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindPhoneLoginTarget(ctx, tn.Slug, "+254722000002"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("primary unverified row: %v", err)
	}
}

// Review M2: the country allow-list keeps signup codes to the listed prefixes; members anywhere
// still sign in.
func TestPhoneSelfSignupPrefixAllowList(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	tn, _ := client.Tenant.Create().SetName("hadia").SetSlug("hadia-" + suffix).SetStatus("active").
		SetMetadata(map[string]any{"phone_self_signup": true, "signup_phone_prefixes": []any{"+254"}}).Save(ctx)
	if target, err := s.FindPhoneLoginTarget(ctx, tn.Slug, "+254733000001"); err != nil || target.Signup == nil {
		t.Fatalf("listed prefix: %+v %v", target, err)
	}
	if _, err := s.FindPhoneLoginTarget(ctx, tn.Slug, "+447700900001"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unlisted prefix: %v", err)
	}
	u, _ := client.User.Create().SetEmail("uk-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	_, _ = client.UserPhone.Create().SetUserID(u.ID).SetPhone("+447700900002").SetIsPrimary(true).Save(ctx)
	_, _ = client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(tn.ID).SetRoles([]string{"hadia_support"}).SetStatus("active").Save(ctx)
	if target, err := s.FindPhoneLoginTarget(ctx, tn.Slug, "+447700900002"); err != nil || target.Signup != nil {
		t.Fatalf("member outside the list: %+v %v", target, err)
	}
}

// Review L7: an account with an authenticator app that joins by phone code gets the membership
// once the authenticator code passes, end to end through the MFA challenge.
func TestPhoneSelfSignupJoinWithMFA(t *testing.T) {
	s, client, tokens := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	tn, _ := client.Tenant.Create().SetName("hadia").SetSlug("hadia-" + suffix).SetStatus("active").
		SetMetadata(map[string]any{"phone_self_signup": true, "self_signup_services": []any{"hadia"}}).Save(ctx)
	u, _ := client.User.Create().SetEmail("mfa-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	const phone = "+254744000001"
	_, _ = client.UserPhone.Create().SetUserID(u.ID).SetPhone(phone).SetIsPrimary(true).SetIsVerified(true).Save(ctx)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: "mfa"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.MFATOTPSecret.Create().SetUserID(u.ID).SetSecret(key.Secret()).SetEnabledAt(time.Now()).Save(ctx); err != nil {
		t.Fatal(err)
	}
	target, err := s.FindPhoneLoginTarget(ctx, tn.Slug, phone)
	if err != nil || target.Signup == nil || target.User == nil {
		t.Fatalf("join target: %+v %v", target, err)
	}
	challenge, err := s.PhoneMFAChallenge(target, "hadia-ui")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteSocialMFA(ctx, SocialMFAInput{Challenge: challenge, Code: "000000"}); !errors.Is(err, ErrMFACodeInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	if ok, _ := client.TenantMembership.Query().Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(tn.ID)).Exist(ctx); ok {
		t.Fatal("a wrong authenticator code created the membership")
	}
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	res, err := s.CompleteSocialMFA(ctx, SocialMFAInput{Challenge: challenge, Code: code})
	if err != nil {
		t.Fatalf("mfa: %v", err)
	}
	m, err := client.TenantMembership.Query().Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(tn.ID)).Only(ctx)
	if err != nil || strings.Join(m.Services, ",") != "hadia" {
		t.Fatalf("membership after mfa: %+v %v", m, err)
	}
	claims, err := tokens.Parse(res.AccessToken)
	if err != nil || strings.Join(claims.UserServices, ",") != "hadia" {
		t.Fatalf("token: %v %v", claims, err)
	}
}

func TestPhoneSignupPolicyBudgetAndPrefixes(t *testing.T) {
	p, _ := TenantPhoneSignupPolicy(&ent.Tenant{Metadata: map[string]any{"phone_self_signup": true}})
	if p.PerMinute != 30 || len(p.Prefixes) != 0 || !p.AllowsPhone("+447700900000") {
		t.Fatalf("defaults: %+v", p)
	}
	p, _ = TenantPhoneSignupPolicy(&ent.Tenant{Metadata: map[string]any{"phone_self_signup": true,
		"signup_otp_per_minute": float64(5), "signup_phone_prefixes": []any{"+254", "255"}}})
	if p.PerMinute != 5 || strings.Join(p.Prefixes, ",") != "+254" || p.AllowsPhone("+255700000000") || !p.AllowsPhone("+254700000000") {
		t.Fatalf("set: %+v", p)
	}
}
