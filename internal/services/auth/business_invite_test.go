package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/google/uuid"
)

// A platform owner invites a new business (owner, 2026-11-11): the invite is a signed token that
// names the email, organisation and app, expires, and is separate from every other token kind.
func TestBusinessInviteRoundTrip(t *testing.T) {
	secret := "test-secret-value" // secret-scan:allow (fake test fixture)
	tok, inv, err := signBusinessInvite(secret, BusinessInvite{Email: "Owner@Shop.co.ke", OrgName: "Shea Glow", UseCase: "fbo", App: "marketflow"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if inv.ID == "" || inv.Email != "owner@shop.co.ke" {
		t.Fatalf("issued: %+v", inv)
	}
	got, err := parseBusinessInvite(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Email != "owner@shop.co.ke" || got.OrgName != "Shea Glow" || got.UseCase != "fbo" || got.App != "marketflow" || got.ID != inv.ID {
		t.Fatalf("parsed: %+v", got)
	}

	if _, err := parseBusinessInvite("another-secret", tok); !errors.Is(err, ErrInvalidBusinessInvite) {
		t.Fatalf("wrong secret: %v", err)
	}
	if _, err := parseBusinessInvite(secret, tok[:len(tok)-2]+"xx"); !errors.Is(err, ErrInvalidBusinessInvite) {
		t.Fatalf("tampered: %v", err)
	}
	expired, _, _ := signBusinessInvite(secret, BusinessInvite{Email: "a@b.co", OrgName: "X", App: "marketflow"}, -time.Minute)
	if _, err := parseBusinessInvite(secret, expired); !errors.Is(err, ErrInvalidBusinessInvite) {
		t.Fatalf("expired: %v", err)
	}
}

func TestBusinessInviteValidation(t *testing.T) {
	for _, in := range []BusinessInvite{
		{Email: "not-an-email", OrgName: "X", App: "marketflow"},
		{Email: "a@b.co", OrgName: " ", App: "marketflow"},
		{Email: "a@b.co", OrgName: "X", App: "evil"},
		{Email: "a@b.co", OrgName: strings.Repeat("x", 121), App: "marketflow"},
		{Email: "a@b.co", OrgName: "X", App: "marketflow", UseCase: "nope"},
	} {
		if _, _, err := signBusinessInvite("s", in, time.Hour); err == nil {
			t.Errorf("%+v: want an error", in)
		}
	}
}

func TestBusinessInviteMatchesEmail(t *testing.T) {
	inv := &BusinessInvite{Email: "owner@shop.co.ke"}
	if !inv.matches(" OWNER@shop.co.ke ") || inv.matches("other@shop.co.ke") {
		t.Fatal("the invite is for one email only")
	}
}

// Signing up with a platform owner's business invite creates the organisation active (no review),
// records the invite, and the same invite can never make a second organisation; a different email
// and a forged metadata key are refused.
func TestRegisterWithBusinessInvite(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	s.hasher = password.NewHasher(config.SecurityConfig{})
	s.cfg.Security.OAuthStateSecret = "invite-test-secret" // secret-scan:allow (fake test fixture)
	ctx := context.Background()
	email := "owner-" + uuid.NewString()[:8] + "@example.com"
	tok, inv, err := s.IssueBusinessInvite(BusinessInvite{Email: email, OrgName: "Shea Glow", UseCase: "fbo", App: "marketflow"})
	if err != nil {
		t.Fatal(err)
	}

	// Another email cannot use it.
	_, err = s.Register(ctx, RegisterInput{Email: "other-" + email, Password: "Str0ng!Passw0rd-x", InviteToken: tok, // secret-scan:allow (fake test fixture)
		OrgAction: "create_new", NewOrg: &NewOrgInput{Name: "Shea Glow", Slug: "shea-" + uuid.NewString()[:8]}})
	if !errors.Is(err, ErrInvalidBusinessInvite) {
		t.Fatalf("other email: %v", err)
	}

	slug := "shea-" + uuid.NewString()[:8]
	if _, err := s.Register(ctx, RegisterInput{Email: email, Password: "Str0ng!Passw0rd-x", InviteToken: tok, // secret-scan:allow (fake test fixture)
		OrgAction: "create_new", NewOrg: &NewOrgInput{Name: "Shea Glow", Slug: slug, Metadata: map[string]any{MetaBusinessInvite: "forged"}}}); err != nil {
		t.Fatalf("invited sign-up: %v", err)
	}
	ten, err := client.Tenant.Query().Where(tenant.SlugEQ(slug)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ten.Status != "active" || ten.Metadata[MetaBusinessInvite] != inv.ID {
		t.Fatalf("invited organisation: status %q, invite %v", ten.Status, ten.Metadata[MetaBusinessInvite])
	}
	if ten.UseCase == nil || *ten.UseCase != "fbo" {
		t.Fatalf("the invite's business type applies: %v", ten.UseCase)
	}

	// Used once: a second organisation from the same invite is refused.
	_, err = s.Register(ctx, RegisterInput{Email: email, Password: "Str0ng!Passw0rd-x", InviteToken: tok, // secret-scan:allow (fake test fixture)
		OrgAction: "create_new", NewOrg: &NewOrgInput{Name: "Again", Slug: "again-" + uuid.NewString()[:8]}})
	if !errors.Is(err, ErrInvalidBusinessInvite) {
		t.Fatalf("second use: %v", err)
	}
}
