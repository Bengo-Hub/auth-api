package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/oauth/state"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/bengobox/auth-api/internal/token"
)

func TestParseMFAPolicy(t *testing.T) {
	cases := []struct {
		name  string
		value any
		ok    bool
		want  MFAPolicy
	}{
		{"absent", nil, false, MFAPolicy{}},
		{"not an object", "on", false, MFAPolicy{}},
		{"empty object is a policy that requires nothing", map[string]any{}, true, MFAPolicy{RequiredRoles: []string{}}},
		{"roles from stored JSON", map[string]any{"required_roles": []any{" hadia_support", "hadia_admin", "hadia_admin", 7, ""}}, true,
			MFAPolicy{RequiredRoles: []string{"hadia_admin", "hadia_support"}}},
		{"roles from the seed", map[string]any{"required_roles": []string{"b", "a"}, "all_accounts": true}, true,
			MFAPolicy{RequiredRoles: []string{"a", "b"}, AllAccounts: true}},
		{"all_accounts as a string is off", map[string]any{"all_accounts": "true"}, true, MFAPolicy{RequiredRoles: []string{}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ParseMFAPolicy(c.value)
			if ok != c.ok || got.AllAccounts != c.want.AllAccounts || strings.Join(got.RequiredRoles, ",") != strings.Join(c.want.RequiredRoles, ",") {
				t.Fatalf("got %+v %v, want %+v %v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestMFAPolicyCovers(t *testing.T) {
	staff := MFAPolicy{RequiredRoles: []string{"hadia_admin", "hadia_finance"}}
	if !staff.Covers([]string{"customer", "hadia_finance"}) {
		t.Fatal("a member holding a required role is covered")
	}
	if staff.Covers([]string{"customer"}) || staff.Covers(nil) {
		t.Fatal("a member without a required role is not covered")
	}
	if !(MFAPolicy{AllAccounts: true}).Covers(nil) {
		t.Fatal("all_accounts covers everyone, roles or not")
	}
	if !(MFAPolicy{}).IsEmpty() || staff.IsEmpty() {
		t.Fatal("IsEmpty")
	}
	// The stored form reads back as the same policy after a JSON round trip.
	raw, _ := json.Marshal(staff.MetadataValue())
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	if p, ok := ParseMFAPolicy(back); !ok || strings.Join(p.RequiredRoles, ",") != "hadia_admin,hadia_finance" {
		t.Fatalf("round trip: %+v %v", p, ok)
	}
}

func TestSessionFactors(t *testing.T) {
	if amr, enroll := sessionFactors(&ent.Session{}); amr != nil || enroll {
		t.Fatalf("a session from before amr: %v %v", amr, enroll)
	}
	meta := sessionFactorsMetadata(map[string]any{"other": 1}, []string{"pwd", "totp", "mfa", "pwd"}, false)
	raw, _ := json.Marshal(meta)
	var stored map[string]any
	_ = json.Unmarshal(raw, &stored)
	amr, enroll := sessionFactors(&ent.Session{Metadata: stored})
	if strings.Join(amr, ",") != "pwd,totp,mfa" || enroll || stored["other"] == nil {
		t.Fatalf("got %v %v from %v", amr, enroll, stored)
	}
	if _, enroll := sessionFactors(&ent.Session{Metadata: sessionFactorsMetadata(nil, []string{"otp"}, true)}); !enroll {
		t.Fatal("enrolment flag lost")
	}
}

// A self-registered organisation can never set what a token grants or what a sign-in must prove.
func TestWithoutPlatformOnlyMetadata(t *testing.T) {
	got := withoutPlatformOnlyMetadata(map[string]any{
		"is_platform_owner": true, "billing_mode": "service_charge", "mfa_policy": map[string]any{},
		"mfa_policy_default": map[string]any{}, "app_url": "https://example.com",
	})
	if len(got) != 1 || got["app_url"] == nil {
		t.Fatalf("got %v", got)
	}
}

// mfaTestWorld is a platform tenant, a tenant whose policy covers hadia_admin, a tenant without a
// policy, and members in them.
type mfaTestWorld struct {
	s                      *Service
	client                 *ent.Client
	tokens                 *token.Service
	platform, hadia, plain *ent.Tenant
}

func newMFATestWorld(t *testing.T) *mfaTestWorld {
	t.Helper()
	s, client, tokens := newPhoneSignupTestService(t)
	s.hasher = password.NewHasher(config.SecurityConfig{})
	ctx := context.Background()
	suffix := uuid.NewString()[:8]
	newTenant := func(slug string, meta map[string]any) *ent.Tenant {
		tn, err := client.Tenant.Create().SetName(slug).SetSlug(slug).SetStatus("active").SetMetadata(meta).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return tn
	}
	return &mfaTestWorld{
		s: s, client: client, tokens: tokens,
		platform: newTenant(platformTenantSlug, map[string]any{"is_platform_owner": true}),
		hadia: newTenant("hadia-"+suffix, map[string]any{
			TenantMetadataMFAPolicy: map[string]any{"required_roles": []string{"hadia_admin", "hadia_finance", "hadia_support"}},
		}),
		plain: newTenant("plain-"+suffix, map[string]any{}),
	}
}

const mfaTestPassword = "Correct-Horse-42"

// member creates an account with a password and a membership; withTOTP adds an enabled
// authenticator and returns its secret.
func (w *mfaTestWorld) member(t *testing.T, tn *ent.Tenant, roles []string, withTOTP bool) (*ent.User, string) {
	t.Helper()
	ctx := context.Background()
	hash, err := w.s.hasher.Hash(mfaTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	u, err := w.client.User.Create().SetEmail(uuid.NewString()[:8] + "@example.com").SetStatus("active").
		SetPasswordHash(hash).SetPrimaryTenantID(tn.ID.String()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(tn.ID).SetRoles(roles).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if !withTOTP {
		return u, ""
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: u.Email})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.client.MFATOTPSecret.Create().SetUserID(u.ID).SetSecret(key.Secret()).SetEnabledAt(time.Now()).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return u, key.Secret()
}

func (w *mfaTestWorld) login(u *ent.User, tn *ent.Tenant, code string) (*AuthResult, error) {
	return w.s.Login(context.Background(), LoginInput{Email: u.Email, Password: mfaTestPassword, TenantSlug: tn.Slug, TOTPCode: code})
}

func (w *mfaTestWorld) claims(t *testing.T, res *AuthResult) *token.Claims {
	t.Helper()
	c, err := w.tokens.Parse(res.AccessToken)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// assertEnrollmentOnly checks an enrolment-only answer: the flag on the result and the token, the
// proven methods without mfa, and nothing a resource server could grant on.
func assertEnrollmentOnly(t *testing.T, w *mfaTestWorld, res *AuthResult, wantAMR string) {
	t.Helper()
	if !res.MFAEnrollmentRequired || len(res.Roles) != 0 || len(res.Permissions) != 0 {
		t.Fatalf("result: enrolment %v roles %v permissions %v", res.MFAEnrollmentRequired, res.Roles, res.Permissions)
	}
	c := w.claims(t, res)
	if !c.MFAEnrollmentRequired || c.HasAMR(AMRMFA) || strings.Join(c.AMR, ",") != wantAMR {
		t.Fatalf("claims: enrolment %v amr %v, want %s", c.MFAEnrollmentRequired, c.AMR, wantAMR)
	}
	if len(c.Roles) != 0 || len(c.Permissions) != 0 || c.UserServices != nil || len(c.ActiveServiceTags) != 0 ||
		c.IsPlatformOwner || c.SubscriptionPlan != "" || len(c.OutletIDs) != 0 {
		t.Fatalf("an enrolment-only token grants: %+v", c)
	}
	if len(c.Audience) != 1 || c.Audience[0] != token.AudienceMFAEnrollment {
		t.Fatalf("audience %v, want only %s", c.Audience, token.AudienceMFAEnrollment)
	}
}

func TestEffectiveMFAPolicy(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()

	p, src, err := w.s.EffectiveMFAPolicy(ctx, w.plain)
	if err != nil || src != MFAPolicyFromPlatform || !p.IsEmpty() {
		t.Fatalf("no policy anywhere requires nothing: %+v %s %v", p, src, err)
	}
	p, src, _ = w.s.EffectiveMFAPolicy(ctx, w.hadia)
	if src != MFAPolicyFromTenant || !p.Covers([]string{"hadia_support"}) {
		t.Fatalf("the tenant's own policy: %+v %s", p, src)
	}

	if _, err := w.s.SetPlatformMFAPolicy(ctx, MFAPolicy{AllAccounts: true}); err != nil {
		t.Fatal(err)
	}
	plain, _ := w.client.Tenant.Get(ctx, w.plain.ID)
	if p, src, _ := w.s.EffectiveMFAPolicy(ctx, plain); src != MFAPolicyFromPlatform || !p.AllAccounts {
		t.Fatalf("the platform default applies to a tenant without its own: %+v %s", p, src)
	}
	hadia, _ := w.client.Tenant.Get(ctx, w.hadia.ID)
	if p, _, _ := w.s.EffectiveMFAPolicy(ctx, hadia); p.AllAccounts {
		t.Fatal("a tenant's own policy wins over the platform default")
	}

	// Inherit removes the tenant's own policy.
	view, err := w.s.SetTenantMFAPolicy(ctx, w.hadia.ID, MFAPolicy{}, true)
	if err != nil || !view.Inherited || !view.Effective.AllAccounts {
		t.Fatalf("inherit: %+v %v", view, err)
	}
	if _, err := w.s.SetTenantMFAPolicy(ctx, uuid.New(), MFAPolicy{}, false); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

func TestPasswordLoginMFA(t *testing.T) {
	w := newMFATestWorld(t)

	t.Run("covered without an authenticator gets an enrolment-only session", func(t *testing.T) {
		u, _ := w.member(t, w.hadia, []string{"hadia_admin"}, false)
		res, err := w.login(u, w.hadia, "")
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentOnly(t, w, res, "pwd")
	})

	t.Run("covered with an authenticator owes the code, then gets mfa", func(t *testing.T) {
		u, secret := w.member(t, w.hadia, []string{"hadia_finance"}, true)
		var owed *MFARequiredError
		if _, err := w.login(u, w.hadia, ""); !errors.As(err, &owed) || owed.UserID != u.ID {
			t.Fatalf("no code: %v", err)
		}
		if n, _ := w.client.Session.Query().Count(context.Background()); n != 1 {
			t.Fatalf("a session was created before the code: %d sessions", n)
		}
		if _, err := w.login(u, w.hadia, "000000"); !errors.Is(err, ErrMFACodeInvalid) {
			t.Fatalf("wrong code: %v", err)
		}
		code, _ := totp.GenerateCode(secret, time.Now())
		res, err := w.login(u, w.hadia, code)
		if err != nil {
			t.Fatal(err)
		}
		c := w.claims(t, res)
		if res.MFAEnrollmentRequired || c.MFAEnrollmentRequired || strings.Join(c.AMR, ",") != "pwd,totp,mfa" {
			t.Fatalf("amr %v enrolment %v", c.AMR, c.MFAEnrollmentRequired)
		}
		if strings.Join(c.Roles, ",") != "hadia_finance" {
			t.Fatalf("roles %v", c.Roles)
		}
	})

	t.Run("not covered signs in as before", func(t *testing.T) {
		u, _ := w.member(t, w.hadia, []string{"customer"}, false)
		res, err := w.login(u, w.hadia, "")
		if err != nil {
			t.Fatal(err)
		}
		c := w.claims(t, res)
		if res.MFAEnrollmentRequired || c.MFAEnrollmentRequired || strings.Join(c.AMR, ",") != "pwd" || strings.Join(c.Roles, ",") != "customer" {
			t.Fatalf("claims %+v", c)
		}
	})

	t.Run("not covered with an authenticator still asks for it", func(t *testing.T) {
		u, _ := w.member(t, w.plain, []string{"admin"}, true)
		var owed *MFARequiredError
		if _, err := w.login(u, w.plain, ""); !errors.As(err, &owed) {
			t.Fatalf("got %v", err)
		}
	})
}

// A shared demo login cannot set up an authenticator, so even an all-accounts rule leaves it
// signing in as before rather than stuck on an enrolment-only session.
func TestDemoLoginsAreNeverCovered(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	if _, err := w.s.SetPlatformMFAPolicy(ctx, MFAPolicy{AllAccounts: true}); err != nil {
		t.Fatal(err)
	}
	demoTenant, err := w.client.Tenant.Create().SetName("Demo").SetSlug("codevertex-demo").SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inDemo, _ := w.member(t, demoTenant, []string{"admin"}, false)
	res, err := w.login(inDemo, demoTenant, "")
	if err != nil || res.MFAEnrollmentRequired {
		t.Fatalf("demo tenant: %v %+v", err, res)
	}
	flagged, _ := w.member(t, w.plain, []string{"cashier"}, false)
	if _, err := w.client.User.UpdateOneID(flagged.ID).SetProfile(map[string]any{"is_demo": true}).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.s.OIDCStepUpFor(ctx, flagged.ID, &w.plain.ID, []string{AMRPassword}); got != OIDCStepUpNone {
		t.Fatalf("demo profile: %v", got)
	}
	ordinary, _ := w.member(t, w.plain, []string{"cashier"}, false)
	if got := w.s.OIDCStepUpFor(ctx, ordinary.ID, &w.plain.ID, []string{AMRPassword}); got != OIDCStepUpEnroll {
		t.Fatalf("an ordinary account is still covered: %v", got)
	}
}

// A lookup error counts as covered and as having an authenticator, so the code is asked for.
func TestMFAStatusFailsClosed(t *testing.T) {
	w := newMFATestWorld(t)
	u, _ := w.member(t, w.plain, []string{"cashier"}, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := w.s.mfaStatusFor(ctx, u.ID, w.plain)
	if !st.covered || !st.hasAuthenticator {
		t.Fatalf("got %+v, want both true", st)
	}
	if _, err := w.s.gateSession(ctx, u, w.plain, []string{AMRPassword}); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("gate: %v", err)
	}
}

func TestOtherSignInPathsMFA(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()

	t.Run("phone code", func(t *testing.T) {
		staff, _ := w.member(t, w.hadia, []string{"hadia_support"}, false)
		res, err := w.s.LoginWithPhoneOTP(ctx, &PhoneLoginTarget{User: staff, Tenant: w.hadia, Phone: "+254700000101"}, "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentOnly(t, w, res, "otp")

		cust, _ := w.member(t, w.hadia, []string{"customer"}, false)
		res, err = w.s.LoginWithPhoneOTP(ctx, &PhoneLoginTarget{User: cust, Tenant: w.hadia, Phone: "+254700000102"}, "", "", "")
		if err != nil || strings.Join(w.claims(t, res).AMR, ",") != "otp" || res.MFAEnrollmentRequired {
			t.Fatalf("customer: %v %+v", err, res)
		}
	})

	t.Run("social provider without an authenticator", func(t *testing.T) {
		staff, _ := w.member(t, w.hadia, []string{"hadia_admin"}, false)
		res, err := w.s.issueSession(ctx, issueSessionInput{User: staff, Tenant: w.hadia, AMR: []string{AMRFederated}})
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentOnly(t, w, res, "fed")
	})

	t.Run("a covered session without the code is refused at issuance", func(t *testing.T) {
		staff, _ := w.member(t, w.hadia, []string{"hadia_admin"}, true)
		if _, err := w.s.issueSession(ctx, issueSessionInput{User: staff, Tenant: w.hadia, AMR: []string{AMRFederated}}); !errors.Is(err, ErrMFARequired) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("social and phone code steps record the second factor", func(t *testing.T) {
		for _, first := range []string{AMRFederated, AMROTP, AMRPasskey} {
			staff, secret := w.member(t, w.hadia, []string{"hadia_admin"}, true)
			pending, err := w.s.socialMFAResult(staff, w.hadia, &state.Payload{FirstFactor: first})
			if err != nil {
				t.Fatal(err)
			}
			code, _ := totp.GenerateCode(secret, time.Now())
			res, err := w.s.CompleteSocialMFA(ctx, SocialMFAInput{Challenge: pending.MFAChallenge, Code: code})
			if err != nil {
				t.Fatalf("%s: %v", first, err)
			}
			if got := strings.Join(w.claims(t, res).AMR, ","); got != first+",totp,mfa" {
				t.Fatalf("%s: amr %s", first, got)
			}
		}
	})

	t.Run("passkey", func(t *testing.T) {
		withApp, _ := w.member(t, w.hadia, []string{"hadia_admin"}, true)
		res, err := w.s.LoginWithWebAuthn(ctx, WebAuthnLoginInput{UserID: withApp.ID, TenantSlug: w.hadia.Slug})
		if err != nil || res.MFAChallenge == "" || res.AccessToken != "" {
			t.Fatalf("covered with an authenticator gets a code step: %v %+v", err, res)
		}
		noApp, _ := w.member(t, w.hadia, []string{"hadia_admin"}, false)
		res, err = w.s.LoginWithWebAuthn(ctx, WebAuthnLoginInput{UserID: noApp.ID, TenantSlug: w.hadia.Slug})
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentOnly(t, w, res, "hwk")
		cust, _ := w.member(t, w.hadia, []string{"customer"}, true)
		res, err = w.s.LoginWithWebAuthn(ctx, WebAuthnLoginInput{UserID: cust.ID, TenantSlug: w.hadia.Slug})
		if err != nil || res.MFAChallenge != "" || strings.Join(w.claims(t, res).AMR, ",") != "hwk" {
			t.Fatalf("not covered signs in with the passkey alone: %v %+v", err, res)
		}
	})

	t.Run("a platform admin's per-user enforcement covers the account", func(t *testing.T) {
		u, _ := w.member(t, w.plain, []string{"cashier"}, false)
		if _, err := w.client.MFASettings.Create().SetUserID(u.ID).SetEnforcedAt(time.Now()).Save(ctx); err != nil {
			t.Fatal(err)
		}
		res, err := w.login(u, w.plain, "")
		if err != nil {
			t.Fatal(err)
		}
		assertEnrollmentOnly(t, w, res, "pwd")
	})
}

func TestRefreshKeepsTheSessionFactors(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()

	staff, secret := w.member(t, w.hadia, []string{"hadia_admin"}, true)
	code, _ := totp.GenerateCode(secret, time.Now())
	signedIn, err := w.login(staff, w.hadia, code)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: signedIn.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.claims(t, refreshed).AMR, ","); got != "pwd,totp,mfa" {
		t.Fatalf("refresh changed amr to %s", got)
	}

	noApp, _ := w.member(t, w.hadia, []string{"hadia_support"}, false)
	enrol, err := w.login(noApp, w.hadia, "")
	if err != nil {
		t.Fatal(err)
	}
	// Setting up the authenticator does not upgrade the session: a refresh stays enrolment-only.
	key, _ := totp.Generate(totp.GenerateOpts{Issuer: "test", AccountName: noApp.Email})
	_, _ = w.client.MFATOTPSecret.Create().SetUserID(noApp.ID).SetSecret(key.Secret()).SetEnabledAt(time.Now()).Save(ctx)
	refreshed, err = w.s.Refresh(ctx, RefreshInput{RefreshToken: enrol.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	assertEnrollmentOnly(t, w, refreshed, "pwd")

	// A policy that comes into force after the sign-in applies at the next refresh.
	cashier, _ := w.member(t, w.plain, []string{"cashier"}, false)
	before, err := w.login(cashier, w.plain, "")
	if err != nil || before.MFAEnrollmentRequired {
		t.Fatalf("before the policy: %v %+v", err, before)
	}
	if _, err := w.s.SetTenantMFAPolicy(ctx, w.plain.ID, MFAPolicy{RequiredRoles: []string{"cashier"}}, false); err != nil {
		t.Fatal(err)
	}
	after, err := w.s.Refresh(ctx, RefreshInput{RefreshToken: before.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	assertEnrollmentOnly(t, w, after, "pwd")
}

func TestOIDCStepUp(t *testing.T) {
	w := newMFATestWorld(t)
	ctx := context.Background()
	withApp, _ := w.member(t, w.hadia, []string{"hadia_admin"}, true)
	noApp, _ := w.member(t, w.hadia, []string{"hadia_admin"}, false)
	cust, _ := w.member(t, w.hadia, []string{"customer"}, false)

	cases := []struct {
		name string
		user uuid.UUID
		amr  []string
		want OIDCStepUp
	}{
		{"covered, authenticator, session without it", withApp.ID, []string{"pwd"}, OIDCStepUpSignIn},
		{"covered, session proved it", withApp.ID, []string{"pwd", "totp", "mfa"}, OIDCStepUpNone},
		{"covered, no authenticator", noApp.ID, []string{"pwd"}, OIDCStepUpEnroll},
		{"not covered", cust.ID, []string{"otp"}, OIDCStepUpNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := w.s.OIDCStepUpFor(ctx, c.user, &w.hadia.ID, c.amr); got != c.want {
				t.Fatalf("by id: %v, want %v", got, c.want)
			}
			if got := w.s.OIDCStepUpForSlug(ctx, c.user, w.hadia.Slug, c.amr); got != c.want {
				t.Fatalf("by slug: %v, want %v", got, c.want)
			}
		})
	}
	// No tenant named: the member's primary tenant decides.
	if got := w.s.OIDCStepUpForSlug(ctx, noApp.ID, "", []string{"pwd"}); got != OIDCStepUpEnroll {
		t.Fatalf("primary tenant: %v", got)
	}
}
