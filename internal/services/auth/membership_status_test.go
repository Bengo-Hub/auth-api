package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
)

// Security audit 2026-11-10 (H2): role lookups ignored the membership status, so a suspended
// or deactivated member kept their roles (and a suspended codevertex admin stayed platform
// owner) on every refresh.
func TestSuspendedMembershipGrantsNothing(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	shop, err := client.Tenant.Create().SetName("Shop").SetSlug("shop-" + sfx).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	platform, err := client.Tenant.Create().SetName("Codevertex").SetSlug(platformTenantSlug).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.User.Create().SetEmail("staff-" + sfx + "@mail.test").SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(shop.ID).SetRoles([]string{"admin"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pm, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(platform.ID).SetRoles([]string{"admin"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if roles, _, _ := s.GetUserRolesAndPermissionsForTenant(ctx, u.ID, shop.ID); len(roles) != 1 {
		t.Fatalf("active member keeps roles: %v", roles)
	}
	if !s.isPlatformOwnerUser(ctx, u.ID) {
		t.Fatal("active codevertex admin is platform owner")
	}

	for _, status := range []string{"suspended", "deactivated"} {
		if _, err := m.Update().SetStatus(status).Save(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := pm.Update().SetStatus(status).Save(ctx); err != nil {
			t.Fatal(err)
		}
		if roles, perms, _ := s.GetUserRolesAndPermissionsForTenant(ctx, u.ID, shop.ID); len(roles)+len(perms) != 0 {
			t.Errorf("%s member got roles %v perms %v", status, roles, perms)
		}
		if s.isPlatformOwnerUser(ctx, u.ID) {
			t.Errorf("%s codevertex admin is still platform owner", status)
		}
		if s.hasActiveMembership(ctx, u.ID, shop.ID) {
			t.Errorf("%s membership counted as active", status)
		}
	}
	if s.hasActiveMembership(ctx, u.ID, uuid.New()) {
		t.Error("no membership is not active")
	}
}

// H2: a member removed or suspended after signing in must not keep refreshing into the tenant,
// and must never pick up roles they hold in another tenant through the old cross-tenant union.
func TestRefreshRefusedAfterMembershipEnds(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	u, _ := w.member(t, w.plain, []string{"member"}, false)
	// The same person is admin of another tenant.
	if _, err := w.client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(w.hadia.ID).SetRoles([]string{"admin"}).Save(ctx); err != nil {
		t.Fatal(err)
	}
	signedIn, err := w.login(u, w.plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: signedIn.RefreshToken}); err != nil {
		t.Fatalf("active member refreshes: %v", err)
	}

	w.client.TenantMembership.Update().
		Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(w.plain.ID)).
		SetStatus("suspended").ExecX(ctx)
	res, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: signedIn.RefreshToken})
	if err == nil {
		t.Fatalf("suspended member refreshed into the tenant with roles %v", w.claims(t, res).Roles)
	}
	if err != ErrNotTenantMember {
		t.Fatalf("got %v, want ErrNotTenantMember", err)
	}
}
