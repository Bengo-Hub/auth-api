package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
	"github.com/bengobox/auth-api/internal/services/mfa"
)

// Review finding 1: a platform owner signs in to any tenant without a membership there. Naming a
// tenant with no policy must not skip the code their platform role owes.
func TestPlatformOwnerCannotSkipMFAByNamingAnotherTenant(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	if _, err := w.s.SetPlatformMFAPolicy(ctx, MFAPolicy{RequiredRoles: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	owner, secret := w.member(t, w.platform, []string{"admin"}, true)

	if _, err := w.login(owner, w.plain, ""); !isMFARequired(err) {
		t.Fatalf("password alone on another tenant: %v, want the code asked for", err)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	res, err := w.login(owner, w.plain, code)
	if err != nil || !w.claims(t, res).HasAMR(AMRMFA) {
		t.Fatalf("with the code: %v", err)
	}
}

// Review finding 2: roles that leak in from a covered tenant are covered by that tenant's rule,
// wherever the sign-in names.
func TestCoverageFollowsEveryMembership(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	staff, _ := w.member(t, w.hadia, []string{"hadia_admin"}, false)
	if _, err := w.client.TenantMembership.Create().SetUserID(staff.ID).SetTenantID(w.plain.ID).SetRoles([]string{}).Save(ctx); err != nil {
		t.Fatal(err)
	}
	plain, _ := w.client.Tenant.Get(ctx, w.plain.ID)
	covered, err := w.s.mfaCovers(ctx, staff.ID, plain)
	if err != nil || !covered {
		t.Fatalf("a hadia_admin signing in to a tenant without a policy: covered %v %v, want covered", covered, err)
	}
	other, _ := w.member(t, w.plain, []string{"admin"}, false)
	if covered, err := w.s.mfaCovers(ctx, other.ID, plain); err != nil || covered {
		t.Fatalf("a member of an uncovered tenant only: covered %v %v", covered, err)
	}
}

// Review findings 4 and 5: tenant metadata is_demo (which a tenant admin could write) exempts no one,
// and a registrant cannot give themselves the profile flag a platform admin uses for demo logins.
func TestDemoExemptionIgnoresWritableFlags(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	hadia, err := w.client.Tenant.UpdateOneID(w.hadia.ID).
		SetMetadata(map[string]any{
			TenantMetadataMFAPolicy: map[string]any{"required_roles": []string{"hadia_admin"}},
			"is_demo":               true,
		}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	staff, _ := w.member(t, hadia, []string{"hadia_admin"}, false)
	if covered, err := w.s.mfaCovers(ctx, staff.ID, hadia); err != nil || !covered {
		t.Fatalf("tenant metadata is_demo must not exempt: covered %v %v", covered, err)
	}
	if !IsPlatformOnlyMetadataKey("is_demo") {
		t.Fatal("is_demo must be a platform-only tenant metadata key")
	}
	if got := withoutRegistrantOnlyKeys(map[string]any{"is_demo": true, "phone": "x"}); got["is_demo"] != nil || got["phone"] != "x" {
		t.Fatalf("registration profile: %v", got)
	}
}

// Review finding 3: an enabled authenticator is replaced only with its current code, and a confirm
// ends the account's other enrolment-only sessions.
func TestAuthenticatorReplacementNeedsTheCurrentCode(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	svc := mfa.New(w.client, "test")
	u, secret := w.member(t, w.hadia, []string{"hadia_admin"}, true)

	if _, err := svc.StartTOTP(ctx, u.ID, u.Email, ""); !errors.Is(err, mfa.ErrAuthenticatorExists) {
		t.Fatalf("start without the current code: %v", err)
	}
	if _, err := svc.StartTOTP(ctx, u.ID, u.Email, "000000"); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("start with a wrong code: %v", err)
	}
	rec := w.client.MFATOTPSecret.Query().Where(mfatotpsecret.UserID(u.ID)).OnlyX(ctx)
	if rec.Secret != secret || rec.EnabledAt.IsZero() {
		t.Fatal("a refused start changed the authenticator")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if _, err := svc.StartTOTP(ctx, u.ID, u.Email, code); err != nil {
		t.Fatalf("start with the current code: %v", err)
	}

	keep := w.client.Session.Create().SetUserID(u.ID).SetRefreshTokenHash(uuid.NewString()).SetSessionType("user").
		SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).
		SetMetadata(map[string]any{"mfa_enrollment_required": true}).SaveX(ctx)
	stale := w.client.Session.Create().SetUserID(u.ID).SetRefreshTokenHash(uuid.NewString()).SetSessionType("user").
		SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).
		SetMetadata(map[string]any{"mfa_enrollment_required": true}).SaveX(ctx)
	full := w.client.Session.Create().SetUserID(u.ID).SetRefreshTokenHash(uuid.NewString()).SetSessionType("user").
		SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	n, err := svc.RevokeOtherEnrollmentSessions(ctx, u.ID, keep.ID)
	if err != nil || n != 1 {
		t.Fatalf("revoked %d %v, want 1", n, err)
	}
	for id, want := range map[uuid.UUID]string{keep.ID: "active", stale.ID: "revoked", full.ID: "active"} {
		if got := w.client.Session.GetX(ctx, id).Status; got != want {
			t.Fatalf("session status %s, want %s", got, want)
		}
	}

	if has, _ := svc.HasUnusedBackupCodes(ctx, u.ID); has {
		t.Fatal("no backup codes yet")
	}
	if _, err := svc.RegenerateBackupCodes(ctx, u.ID, 2); err != nil {
		t.Fatal(err)
	}
	if has, _ := svc.HasUnusedBackupCodes(ctx, u.ID); !has {
		t.Fatal("backup codes not seen")
	}
}

// Review finding 7: a platform owner can reset a lost authenticator.
func TestResetUserMFA(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	u, _ := w.member(t, w.hadia, []string{"hadia_admin"}, true)
	w.client.Session.Create().SetUserID(u.ID).SetRefreshTokenHash(uuid.NewString()).SetSessionType("user").
		SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)

	res, err := w.s.ResetUserMFA(ctx, u.ID)
	if err != nil || !res.HadAuthenticator || res.SessionsRevoked != 1 {
		t.Fatalf("reset: %+v %v", res, err)
	}
	if on, _ := w.s.IsMFAEnabled(ctx, u.ID); on {
		t.Fatal("the authenticator survived the reset")
	}
	// The covered account now enrols again at its next sign-in.
	out, err := w.login(u, w.hadia, "")
	if err != nil {
		t.Fatal(err)
	}
	assertEnrollmentOnly(t, w, out, "pwd")
	if _, err := w.s.ResetUserMFA(ctx, uuid.New()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func isMFARequired(err error) bool {
	var m *MFARequiredError
	return errors.As(err, &m) || errors.Is(err, ErrMFARequired)
}
