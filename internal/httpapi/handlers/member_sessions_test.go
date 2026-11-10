package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Security audit 2026-11-10 (H2): removing or suspending a member left their sessions in the
// tenant running. Their sessions in that tenant are now revoked at once; their sessions in
// other tenants, and other people's, are left alone.
func TestRevokeMemberSessions(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	a := client.Tenant.Create().SetName("A").SetSlug("a-" + sfx).SetStatus("active").SaveX(ctx)
	b := client.Tenant.Create().SetName("B").SetSlug("b-" + sfx).SetStatus("active").SaveX(ctx)
	u := client.User.Create().SetEmail("u-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	other := client.User.Create().SetEmail("o-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	mk := func(user, tenant uuid.UUID) uuid.UUID {
		return client.Session.Create().SetUserID(user).SetTenantID(tenant).SetRefreshTokenHash(uuid.NewString()).
			SetSessionType("user").SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx).ID
	}
	inA, inB, othersA := mk(u.ID, a.ID), mk(u.ID, b.ID), mk(other.ID, a.ID)

	if n := revokeMemberSessions(ctx, client, a.ID, u.ID); n != 1 {
		t.Fatalf("revoked %d, want 1", n)
	}
	for id, want := range map[uuid.UUID]string{inA: "revoked", inB: "active", othersA: "active"} {
		if got := client.Session.GetX(ctx, id).Status; got != want {
			t.Errorf("session %s: %s, want %s", id, got, want)
		}
	}
}

// H4 / MF #3: an invite used to set a suspended membership back to active.
func TestMemberReAddRefused(t *testing.T) {
	for _, s := range []string{"suspended", "deactivated", "inactive"} {
		if !memberReAddRefused(s) {
			t.Errorf("%s re-add must be refused", s)
		}
	}
	if memberReAddRefused("active") || memberReAddRefused("") {
		t.Error("an active member can be updated")
	}
}

// Security audit 2026-11-10 (H3): a tenant admin could add an existing account by email with a
// phone they control, then sign in by phone code as that person (with their access in every
// tenant). An admin may attach a phone only to an account that is theirs alone.
func TestAccountOnlyInTenant(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	a := client.Tenant.Create().SetName("A").SetSlug("a-" + sfx).SetStatus("active").SaveX(ctx)
	b := client.Tenant.Create().SetName("B").SetSlug("b-" + sfx).SetStatus("active").SaveX(ctx)
	solo := client.User.Create().SetEmail("solo-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	shared := client.User.Create().SetEmail("shared-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	fresh := client.User.Create().SetEmail("fresh-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	client.TenantMembership.Create().SetUserID(solo.ID).SetTenantID(a.ID).SetRoles([]string{"member"}).SaveX(ctx)
	client.TenantMembership.Create().SetUserID(shared.ID).SetTenantID(a.ID).SetRoles([]string{"member"}).SaveX(ctx)
	client.TenantMembership.Create().SetUserID(shared.ID).SetTenantID(b.ID).SetRoles([]string{"admin"}).SaveX(ctx)

	if !accountOnlyInTenant(ctx, client, solo.ID, a.ID) {
		t.Error("an account only in this tenant may get a phone")
	}
	if !accountOnlyInTenant(ctx, client, fresh.ID, a.ID) {
		t.Error("an account in no tenant yet may get a phone")
	}
	if accountOnlyInTenant(ctx, client, shared.ID, a.ID) {
		t.Error("an account that also belongs to another tenant must not get an admin-set phone")
	}
}
