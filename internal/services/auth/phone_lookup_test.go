package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// LookupVerifiedPhone matches only a verified phone on an account that can sign in, and lists only
// that account's active memberships (the S2S phone lookup for marketflow-api's WhatsApp worker).
func TestLookupVerifiedPhone(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]

	acme, err := client.Tenant.Create().SetName("acme").SetSlug("acme-" + suffix).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := client.Tenant.Create().SetName("other").SetSlug("other-" + suffix).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	known, err := client.User.Create().SetEmail("known-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UserPhone.Create().SetUserID(known.ID).SetPhone("+254733000001").SetIsPrimary(true).SetIsVerified(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := client.TenantMembership.Create().SetUserID(known.ID).SetTenantID(acme.ID).SetRoles([]string{"admin"}).SetStatus("active").Save(ctx); err != nil {
		t.Fatal(err)
	}
	// A suspended membership is not listed.
	if _, err := client.TenantMembership.Create().SetUserID(known.ID).SetTenantID(other.ID).SetRoles([]string{"customer"}).SetStatus("suspended").Save(ctx); err != nil {
		t.Fatal(err)
	}

	got, err := s.LookupVerifiedPhone(ctx, "+254733000001")
	if err != nil {
		t.Fatalf("verified phone: %v", err)
	}
	if got.UserID != known.ID || !got.PhoneVerified || len(got.Tenants) != 1 || got.Tenants[0].Slug != acme.Slug || got.Tenants[0].Roles[0] != "admin" {
		t.Fatalf("lookup = %+v", got)
	}

	// An unverified phone never matches: anyone can attach an unproven number to an account.
	squatter, _ := client.User.Create().SetEmail("squat-" + suffix + "@mail.test").SetStatus("active").Save(ctx)
	if _, err := client.UserPhone.Create().SetUserID(squatter.ID).SetPhone("+254733000002").SetIsVerified(false).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupVerifiedPhone(ctx, "+254733000002"); !errors.Is(err, ErrPhoneNotFound) {
		t.Fatalf("unverified phone matched: %v", err)
	}

	// An account that cannot sign in is treated as unknown.
	blocked, _ := client.User.Create().SetEmail("blocked-" + suffix + "@mail.test").SetStatus("suspended").Save(ctx)
	if _, err := client.UserPhone.Create().SetUserID(blocked.ID).SetPhone("+254733000003").SetIsPrimary(true).SetIsVerified(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupVerifiedPhone(ctx, "+254733000003"); !errors.Is(err, ErrPhoneNotFound) {
		t.Fatalf("suspended account matched: %v", err)
	}

	if _, err := s.LookupVerifiedPhone(ctx, "+254733000999"); !errors.Is(err, ErrPhoneNotFound) {
		t.Fatalf("unknown phone: %v", err)
	}
}
