package handlers

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/userphone"
)

// A resident first invited by phone gets a placeholder account. When the estate later invites the
// same person with their real email, the phone must move to the real account, or phone code
// sign-in finds the placeholder and silently sends nothing.
func TestAttachPhoneReclaimsPlaceholder(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	h := &AdminHandler{ent: client, logger: zap.NewNop()}

	tenant := func(name string) *ent.Tenant {
		tn, err := client.Tenant.Create().SetName(name).SetSlug(name + "-" + uuid.NewString()[:8]).SetStatus("active").Save(ctx)
		if err != nil {
			t.Fatalf("tenant: %v", err)
		}
		return tn
	}
	user := func(email string) *ent.User {
		u, err := client.User.Create().SetEmail(email).SetPasswordHash("x").SetStatus("active").Save(ctx)
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		return u
	}
	member := func(u *ent.User, tn *ent.Tenant) {
		if _, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(tn.ID).SetRoles([]string{"maskani_owner"}).SetStatus("active").Save(ctx); err != nil {
			t.Fatalf("membership: %v", err)
		}
	}
	phoneOwner := func(p string) uuid.UUID {
		up, err := client.UserPhone.Query().Where(userphone.PhoneEQ(p)).Only(ctx)
		if err != nil {
			t.Fatalf("phone lookup: %v", err)
		}
		return up.UserID
	}
	suffix := uuid.NewString()[:6]

	t.Run("placeholder in this tenant only moves", func(t *testing.T) {
		estate := tenant("estate")
		phone := "+254700" + "100" + "001"
		ph := user("p254700100001-" + suffix + "@placeholder.local")
		member(ph, estate)
		if _, err := client.UserPhone.Create().SetUserID(ph.ID).SetPhone(phone).SetIsPrimary(true).Save(ctx); err != nil {
			t.Fatal(err)
		}
		real := user("resident-" + suffix + "@mail.test")

		h.attachPhoneIfFree(ctx, estate.ID, real.ID, phone)

		if got := phoneOwner(phone); got != real.ID {
			t.Fatalf("phone still on %v, want the real account", got)
		}
		st, _ := client.TenantMembership.Query().Where(tenantmembership.UserID(ph.ID), tenantmembership.TenantID(estate.ID)).Only(ctx)
		if st == nil || st.Status != "deactivated" {
			t.Fatalf("placeholder membership not retired: %+v", st)
		}
	})

	t.Run("placeholder with access elsewhere stays", func(t *testing.T) {
		estate, other := tenant("estate2"), tenant("other")
		phone := "+254700" + "100" + "002"
		ph := user("p254700100002-" + suffix + "@placeholder.local")
		member(ph, estate)
		member(ph, other)
		if _, err := client.UserPhone.Create().SetUserID(ph.ID).SetPhone(phone).SetIsPrimary(true).Save(ctx); err != nil {
			t.Fatal(err)
		}
		real := user("resident2-" + suffix + "@mail.test")

		h.attachPhoneIfFree(ctx, estate.ID, real.ID, phone)

		if got := phoneOwner(phone); got != ph.ID {
			t.Fatal("phone moved off a placeholder that belongs to another tenant")
		}
	})

	t.Run("real account keeps its phone", func(t *testing.T) {
		estate := tenant("estate3")
		phone := "+254700" + "100" + "003"
		holder := user("holder-" + suffix + "@mail.test")
		if _, err := client.UserPhone.Create().SetUserID(holder.ID).SetPhone(phone).SetIsPrimary(true).Save(ctx); err != nil {
			t.Fatal(err)
		}
		real := user("resident3-" + suffix + "@mail.test")

		h.attachPhoneIfFree(ctx, estate.ID, real.ID, phone)

		if got := phoneOwner(phone); got != holder.ID {
			t.Fatal("phone taken from a real account")
		}
	})

	t.Run("free phone is attached", func(t *testing.T) {
		estate := tenant("estate4")
		phone := "+254700" + "100" + "004"
		real := user("resident4-" + suffix + "@mail.test")

		h.attachPhoneIfFree(ctx, estate.ID, real.ID, phone)

		if got := phoneOwner(phone); got != real.ID {
			t.Fatal("free phone not attached")
		}
	})
}
