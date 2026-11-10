package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
)

// Security audit 2026-11-10 (C1): "create a new organisation" with the slug of an existing one
// used to fall back to that organisation and make the registrant its admin, so anyone could
// become admin (and, for "codevertex", platform owner) of any tenant with only their own email.
func TestRegisterCreateNewNeverTakesOverAnExistingTenant(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	slug := "victim-" + uuid.NewString()[:8]
	victim, err := client.Tenant.Create().SetName("Victim").SetSlug(slug).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	email := "attacker-" + uuid.NewString()[:8] + "@example.com"
	_, err = s.Register(ctx, RegisterInput{
		Email: email, Password: "Str0ng!Passw0rd-x", Profile: map[string]any{"name": "Attacker"},
		OrgAction: "create_new", NewOrg: &NewOrgInput{Name: "Victim", Slug: slug},
	})
	if !errors.Is(err, ErrOrgSlugTaken) {
		t.Fatalf("got %v, want ErrOrgSlugTaken", err)
	}
	n, err := client.TenantMembership.Query().
		Where(tenantmembership.TenantID(victim.ID), tenantmembership.HasUserWith(user.EmailEQ(email))).Count(ctx)
	if err != nil || n != 0 {
		t.Fatalf("attacker got %d memberships in the existing tenant (%v)", n, err)
	}
}

func TestRegisterCreateNewRefusesReservedAndMalformedSlugs(t *testing.T) {
	s := &Service{}
	for _, slug := range []string{"codevertex", "codevertex-demo", "admin", "platform", "Bad Slug", "-x", ""} {
		_, err := s.Register(context.Background(), RegisterInput{
			Email: "someone@example.com", Password: "Str0ng!Passw0rd-x",
			OrgAction: "create_new", NewOrg: &NewOrgInput{Name: "X", Slug: slug},
		})
		if !errors.Is(err, ErrOrgSlugTaken) && !errors.Is(err, ErrInvalidOrgSlug) {
			t.Errorf("slug %q: got %v, want ErrOrgSlugTaken or ErrInvalidOrgSlug", slug, err)
		}
	}
}
