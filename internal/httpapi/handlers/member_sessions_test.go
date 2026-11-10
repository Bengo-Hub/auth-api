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
