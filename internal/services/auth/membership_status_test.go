package auth

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent/session"
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

// H2: a suspended member cannot sign in to that tenant with a password.
func TestLoginRefusedForSuspendedMember(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	u, _ := w.member(t, w.plain, []string{"member"}, false)
	if _, err := w.login(u, w.plain, ""); err != nil {
		t.Fatalf("active member signs in: %v", err)
	}
	w.client.TenantMembership.Update().
		Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(w.plain.ID)).
		SetStatus("suspended").ExecX(ctx)
	if _, err := w.login(u, w.plain, ""); err != ErrNotTenantMember {
		t.Fatalf("suspended member: got %v, want ErrNotTenantMember", err)
	}
}

// H2: a social sign-in does not let a suspended member back in.
func TestEnsureMembershipRefusesSuspended(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	u, _ := w.member(t, w.plain, []string{"member"}, false)
	w.client.TenantMembership.Update().
		Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(w.plain.ID)).
		SetStatus("deactivated").ExecX(ctx)
	if err := w.s.ensureMembership(ctx, u, w.plain, "customer"); err != ErrNotTenantMember {
		t.Fatalf("got %v, want ErrNotTenantMember", err)
	}
}

// H2: the customer-app joiner used to answer "joined" for any existing membership, which let a
// suspended member through /authorize.
func TestJoinDoesNotPassSuspendedMember(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	u, _ := w.member(t, w.plain, []string{"customer"}, false)
	w.client.TenantMembership.Update().
		Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(w.plain.ID)).
		SetStatus("suspended").ExecX(ctx)
	joined, err := w.s.joinTenantAs(ctx, u, w.plain, "customer", "self_signup")
	if err != nil || joined {
		t.Fatalf("suspended member joined=%v err=%v", joined, err)
	}
}

// M2: completing a password reset ends every existing session of the account.
func TestPasswordResetRevokesSessions(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	u, _ := w.member(t, w.plain, []string{"member"}, false)
	old := w.client.Session.Create().SetUserID(u.ID).SetRefreshTokenHash(uuid.NewString()).SetSessionType("user").
		SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	link, err := w.s.IssueSetPasswordLink(ctx, u.ID, w.plain.Slug, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(link)
	if err := w.s.ConfirmPasswordReset(ctx, PasswordResetConfirmInput{Token: parsed.Query().Get("token"), NewPassword: "Kiondo!Basket2026x"}); err != nil {
		t.Fatal(err)
	}
	if got := w.client.Session.GetX(ctx, old.ID).Status; got != "revoked" {
		t.Fatalf("old session %s after reset, want revoked", got)
	}
}

// Security audit 2026-11-10 (L3): a rotated refresh token presented again long after rotation
// means it was copied; the session is revoked. Within a short grace window (two tabs refreshing
// at once) it is only refused.
func TestRefreshTokenReuseRevokesSession(t *testing.T) {
	w := newMFATestWorld(t)
	w.s.cfg.Token.RotateRefreshTokens = true // production default (ROTATE_REFRESH=true)
	ctx := context.Background()
	u, _ := w.member(t, w.plain, []string{"member"}, false)
	signedIn, err := w.login(u, w.plain, "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: signedIn.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	// Within the grace window: refused, session kept.
	if _, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: signedIn.RefreshToken}); err != ErrInvalidCredentials {
		t.Fatalf("reuse within grace: %v", err)
	}
	if _, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); err != nil {
		t.Fatalf("the current token still works after a benign race: %v", err)
	}
	// Age the rotation past the grace window, then replay the oldest token.
	sess := w.client.Session.Query().Where(session.UserID(u.ID), session.StatusEQ("active")).OnlyX(ctx)
	meta := sess.Metadata
	meta[refreshRotatedAtKey] = time.Now().Add(-10 * time.Minute).Format(time.RFC3339)
	meta[refreshPrevHashKey] = hashToken(first.RefreshToken)
	sess.Update().SetMetadata(meta).ExecX(ctx)
	if _, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken}); err != ErrInvalidCredentials {
		t.Fatalf("stale reuse: %v", err)
	}
	if got := w.client.Session.GetX(ctx, sess.ID).Status; got != "revoked" {
		t.Fatalf("session after stale reuse: %s, want revoked", got)
	}
}
