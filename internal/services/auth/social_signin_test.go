package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
	"github.com/bengobox/auth-api/internal/oauth/state"
	githubprovider "github.com/bengobox/auth-api/internal/providers/github"
	googleprovider "github.com/bengobox/auth-api/internal/providers/google"
	microsoftprovider "github.com/bengobox/auth-api/internal/providers/microsoft"
	tiktokprovider "github.com/bengobox/auth-api/internal/providers/tiktok"
)

// fakeGoogle answers every code with the profile set on it.
type fakeGoogle struct{ profile googleprovider.Profile }

func (f *fakeGoogle) AuthCodeURL(_ context.Context, st string) (string, error) {
	return "https://accounts.google.test/auth?state=" + st, nil
}
func (f *fakeGoogle) Exchange(_ context.Context, _ string) (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "g"}, nil
}
func (f *fakeGoogle) FetchProfile(_ context.Context, _ *oauth2.Token) (*googleprovider.Profile, error) {
	p := f.profile
	return &p, nil
}

func idTokenWith(t *testing.T, claims jwt.MapClaims) *oauth2.Token {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("unit-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return (&oauth2.Token{AccessToken: "m"}).WithExtra(map[string]any{"id_token": raw})
}

// TestProviderAdaptersTrustOnlyProvenEmails is the per-provider half of the matrix: which email a
// provider's answer may match an existing account by.
func TestProviderAdaptersTrustOnlyProvenEmails(t *testing.T) {
	cases := []struct {
		name        string
		sp          *SocialProfile
		wantEmail   string
		wantTrusted bool
	}{
		{"google verified", googleSocialProfile(&googleprovider.Profile{Subject: "1", Email: "a@x.org", EmailVerified: true}, nil), "a@x.org", true},
		{"google unverified", googleSocialProfile(&googleprovider.Profile{Subject: "1", Email: "a@x.org"}, nil), "a@x.org", false},
		{"github primary verified", githubSocialProfile(&githubprovider.Profile{ID: 7, Email: "public@x.org", VerifiedEmail: "a@x.org"}, nil), "a@x.org", true},
		{"github public email only", githubSocialProfile(&githubprovider.Profile{ID: 7, Email: "public@x.org"}, nil), "public@x.org", false},
		{"microsoft graph mail", microsoftSocialProfile(&microsoftprovider.Profile{ID: "m", Mail: "a@x.org"}, &oauth2.Token{}), "a@x.org", false},
		{"microsoft upn", microsoftSocialProfile(&microsoftprovider.Profile{ID: "m", UserPrincipalName: "a@x.org"}, nil), "a@x.org", false},
		{"microsoft xms_edov", microsoftSocialProfile(&microsoftprovider.Profile{ID: "m", Mail: "other@x.org"},
			idTokenWith(t, jwt.MapClaims{"email": "a@x.org", "xms_edov": true})), "a@x.org", true},
		{"tiktok", tiktokSocialProfile(&tiktokprovider.Profile{OpenID: "o"}, nil), "", false},
	}
	for _, c := range cases {
		if c.sp.Email != c.wantEmail || c.sp.EmailTrusted != c.wantTrusted {
			t.Errorf("%s: email %q trusted %v, want %q %v", c.name, c.sp.Email, c.sp.EmailTrusted, c.wantEmail, c.wantTrusted)
		}
	}
}

type socialFixture struct {
	s        *Service
	client   *ent.Client
	platform *ent.Tenant
	staff    *ent.Tenant
}

func newSocialFixture(t *testing.T) *socialFixture {
	t.Helper()
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	platform, err := client.Tenant.Query().Where(tenant.SlugEQ(platformTenantSlug)).Only(ctx)
	if err != nil {
		if platform, err = client.Tenant.Create().SetName("Codevertex").SetSlug(platformTenantSlug).SetStatus("active").Save(ctx); err != nil {
			t.Fatal(err)
		}
	}
	staff, err := client.Tenant.Create().SetName("Staff Org").SetSlug("staff-" + uuid.NewString()[:8]).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &socialFixture{s: s, client: client, platform: platform, staff: staff}
}

// member creates an account that belongs to the staff tenant.
func (f *socialFixture) member(t *testing.T, email string) *ent.User {
	t.Helper()
	ctx := context.Background()
	u, err := f.client.User.Create().SetEmail(email).SetStatus(UserStatusActive).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(f.staff.ID).SetRoles([]string{"member"}).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return u
}

func (f *socialFixture) identities(provider, subject string) int {
	n, _ := f.client.UserIdentity.Query().Where(useridentity.ProviderEQ(provider), useridentity.ProviderSubjectEQ(subject)).Count(context.Background())
	return n
}

// TestResolveSocialUserMatrix runs every provider through the shared resolver.
func TestResolveSocialUserMatrix(t *testing.T) {
	f := newSocialFixture(t)
	ctx := context.Background()
	for _, provider := range []string{googleProviderName, githubProviderName, microsoftProviderName, tiktokProviderName} {
		provider := provider
		hasEmail := provider != tiktokProviderName
		profile := func(email string, trusted bool) *SocialProfile {
			sp := &SocialProfile{Provider: provider, Subject: provider + "-" + uuid.NewString(), Name: "Achieng", Profile: map[string]any{"name": "Achieng"}}
			if hasEmail {
				sp.Email, sp.EmailTrusted = email, trusted
			}
			return sp
		}
		fresh := func() string { return provider + "-" + uuid.NewString()[:8] + "@example.org" }

		t.Run(provider+"/identity hit lands in the linked account whatever the email", func(t *testing.T) {
			u := f.member(t, fresh())
			sp := profile(fresh(), true)
			if err := f.s.createIdentity(ctx, u.ID, sp); err != nil {
				t.Fatal(err)
			}
			got, err := f.s.resolveSocialUser(ctx, f.staff, "member", sp)
			if err != nil || got.ID != u.ID {
				t.Fatalf("got %v err %v, want %s", got, err, u.ID)
			}
		})

		if hasEmail {
			t.Run(provider+"/trusted email links the existing account", func(t *testing.T) {
				u := f.member(t, fresh())
				sp := profile(u.Email, true)
				got, err := f.s.resolveSocialUser(ctx, f.staff, "member", sp)
				if err != nil || got.ID != u.ID {
					t.Fatalf("got %v err %v, want %s", got, err, u.ID)
				}
				if f.identities(provider, sp.Subject) != 1 || !got.EmailVerified {
					t.Fatalf("identity not linked or email not promoted (verified=%v)", got.EmailVerified)
				}
			})

			t.Run(provider+"/untrusted email never links", func(t *testing.T) {
				u := f.member(t, fresh())
				sp := profile(u.Email, false)
				before, _ := f.client.User.Query().Count(ctx)
				if _, err := f.s.resolveSocialUser(ctx, f.platform, "member", sp); !errors.Is(err, ErrSocialEmailInUse) {
					t.Fatalf("err = %v, want ErrSocialEmailInUse", err)
				}
				after, _ := f.client.User.Query().Count(ctx)
				if after != before || f.identities(provider, sp.Subject) != 0 {
					t.Fatalf("untrusted email changed accounts: users %d->%d", before, after)
				}
			})

			t.Run(provider+"/new person with a trusted email gets a verified account", func(t *testing.T) {
				sp := profile(fresh(), true)
				got, err := f.s.resolveSocialUser(ctx, f.platform, "member", sp)
				if err != nil {
					t.Fatal(err)
				}
				if got.Email != sp.Email || !got.EmailVerified || f.identities(provider, sp.Subject) != 1 {
					t.Fatalf("account %q verified=%v", got.Email, got.EmailVerified)
				}
			})
		}

		t.Run(provider+"/new person without a trusted email gets a placeholder", func(t *testing.T) {
			sp := profile(fresh(), false)
			got, err := f.s.resolveSocialUser(ctx, f.platform, "member", sp)
			if err != nil {
				t.Fatal(err)
			}
			if !IsPlaceholderEmail(got.Email) || got.EmailVerified || !strings.HasPrefix(got.Email, provider+"-") {
				t.Fatalf("account %q verified=%v, want an unverified placeholder", got.Email, got.EmailVerified)
			}
			if profileStr(got.Profile, "signup_method") != provider {
				t.Fatalf("profile = %v", got.Profile)
			}
		})

		t.Run(provider+"/refused sign-up leaves no account", func(t *testing.T) {
			sp := profile(fresh(), true)
			before, _ := f.client.User.Query().Count(ctx)
			if _, err := f.s.resolveSocialUser(ctx, f.staff, "member", sp); !errors.Is(err, ErrTenantMembershipRequired) {
				t.Fatalf("err = %v", err)
			}
			after, _ := f.client.User.Query().Count(ctx)
			if after != before || f.identities(provider, sp.Subject) != 0 {
				t.Fatalf("refused sign-up left data: users %d->%d", before, after)
			}
		})
	}
}

// TestSocialLinkFlow covers linking from Account settings: the signed state, the session check at
// the callback, the conflict with another account and the sign-in afterwards.
func TestSocialLinkFlow(t *testing.T) {
	f := newSocialFixture(t)
	ctx := context.Background()
	fake := &fakeGoogle{}
	f.s.google = fake
	owner := f.member(t, "owner-"+uuid.NewString()[:8]+"@example.org")
	other := f.member(t, "other-"+uuid.NewString()[:8]+"@example.org")
	googleSub := "g-" + uuid.NewString()
	// A Google account whose email differs from the SSO account's: sign-in alone would never find it.
	fake.profile = googleprovider.Profile{Subject: googleSub, Email: "personal-" + uuid.NewString()[:8] + "@gmail.test", EmailVerified: true, Name: "Owner"}

	linkState := func(t *testing.T, userID uuid.UUID) string {
		t.Helper()
		u, err := f.s.StartSocialLink(ctx, googleProviderName, userID, OAuthStartInput{})
		if err != nil {
			t.Fatal(err)
		}
		return u[strings.Index(u, "state=")+len("state="):]
	}

	t.Run("the state carries the link flow and the person", func(t *testing.T) {
		p, err := state.Decode(f.s.cfg.Security.OAuthStateSecret, linkState(t, owner.ID))
		if err != nil || p.Flow != socialLinkFlow || p.UserID != owner.ID.String() || p.Purpose != "" {
			t.Fatalf("state %+v err %v", p, err)
		}
	})

	t.Run("a public start cannot ask for the link flow", func(t *testing.T) {
		if _, err := f.s.StartGoogleOAuth(ctx, OAuthStartInput{TenantSlug: f.staff.Slug, Flow: "link"}); !errors.Is(err, ErrOAuthStateInvalid) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a callback without the same session is refused", func(t *testing.T) {
		st := linkState(t, owner.ID)
		for _, sess := range []uuid.UUID{uuid.Nil, other.ID} {
			_, err := f.s.CompleteGoogleOAuth(ctx, OAuthCallbackInput{Code: "c", State: st, SessionUserID: sess})
			var le *SocialLinkError
			if !errors.As(err, &le) || !errors.Is(err, ErrSocialLinkSessionMismatch) {
				t.Fatalf("session %s: err = %v", sess, err)
			}
		}
		if f.identities(googleProviderName, googleSub) != 0 {
			t.Fatal("identity linked without the owner's session")
		}
	})

	t.Run("a tampered state is refused", func(t *testing.T) {
		st := linkState(t, owner.ID)
		parts := strings.Split(st, ".")
		// Re-sign the same claims with another person's id and a key that is not ours.
		forged, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"flow": "link", "user_id": other.ID.String()}).SignedString([]byte("not-the-secret"))
		for _, bad := range []string{parts[0] + "." + parts[1] + ".AAAA", forged} {
			if _, err := f.s.CompleteGoogleOAuth(ctx, OAuthCallbackInput{Code: "c", State: bad, SessionUserID: other.ID}); !errors.Is(err, ErrOAuthStateInvalid) {
				t.Fatalf("err = %v", err)
			}
		}
	})

	t.Run("the owner links Google to their own account", func(t *testing.T) {
		res, err := f.s.CompleteGoogleOAuth(ctx, OAuthCallbackInput{Code: "c", State: linkState(t, owner.ID), SessionUserID: owner.ID})
		if err != nil {
			t.Fatal(err)
		}
		if res.LinkedProvider != googleProviderName || res.AccessToken != "" {
			t.Fatalf("result %+v", res)
		}
		ident, err := f.client.UserIdentity.Query().Where(useridentity.ProviderEQ(googleProviderName), useridentity.ProviderSubjectEQ(googleSub)).Only(ctx)
		if err != nil || ident.UserID != owner.ID {
			t.Fatalf("identity %+v err %v", ident, err)
		}
	})

	t.Run("Login with Google now lands in the owner's account", func(t *testing.T) {
		st, _ := state.Encode(f.s.cfg.Security.OAuthStateSecret, state.Payload{TenantSlug: f.staff.Slug, Flow: "login", Nonce: randomNonce()}, oauthStateTTL)
		res, err := f.s.CompleteGoogleOAuth(ctx, OAuthCallbackInput{Code: "c", State: st})
		if err != nil {
			t.Fatal(err)
		}
		if res.User.ID != owner.ID {
			t.Fatalf("signed in as %s, want %s", res.User.ID, owner.ID)
		}
		if n, _ := f.client.User.Query().Where(user.EmailEQ(fake.profile.Email)).Count(ctx); n != 0 {
			t.Fatal("a separate account was created for the Google email")
		}
	})

	t.Run("the same Google account cannot be linked to someone else", func(t *testing.T) {
		_, err := f.s.CompleteGoogleOAuth(ctx, OAuthCallbackInput{Code: "c", State: linkState(t, other.ID), SessionUserID: other.ID})
		var le *SocialLinkError
		if !errors.As(err, &le) || !errors.Is(err, ErrSocialIdentityLinkedElsewhere) {
			t.Fatalf("err = %v", err)
		}
		ident, _ := f.client.UserIdentity.Query().Where(useridentity.ProviderEQ(googleProviderName), useridentity.ProviderSubjectEQ(googleSub)).Only(ctx)
		if ident.UserID != owner.ID {
			t.Fatal("identity moved to another account")
		}
	})
}

// TestUnlinkKeepsAWayToSignIn: never the last sign-in method.
func TestUnlinkKeepsAWayToSignIn(t *testing.T) {
	f := newSocialFixture(t)
	ctx := context.Background()
	u := f.member(t, "unlink-"+uuid.NewString()[:8]+"@example.org")
	link := func(provider string) uuid.UUID {
		sub := uuid.NewString()
		if err := f.s.createIdentity(ctx, u.ID, &SocialProfile{Provider: provider, Subject: sub}); err != nil {
			t.Fatal(err)
		}
		id, _ := f.client.UserIdentity.Query().Where(useridentity.ProviderSubjectEQ(sub)).OnlyID(ctx)
		return id
	}
	google, tiktok := link(googleProviderName), link(tiktokProviderName)

	rows, hasPassword, err := f.s.SocialIdentities(ctx, u.ID)
	if err != nil || len(rows) != 2 || hasPassword {
		t.Fatalf("rows %d password %v err %v", len(rows), hasPassword, err)
	}
	if err := f.s.UnlinkSocialIdentity(ctx, u.ID, google, "", ""); err != nil {
		t.Fatalf("unlink with another method left: %v", err)
	}
	if err := f.s.UnlinkSocialIdentity(ctx, u.ID, tiktok, "", ""); !errors.Is(err, ErrLastSignInMethod) {
		t.Fatalf("last method: err = %v", err)
	}
	stranger := f.member(t, "stranger-"+uuid.NewString()[:8]+"@example.org")
	if err := f.s.UnlinkSocialIdentity(ctx, stranger.ID, tiktok, "", ""); !errors.Is(err, ErrSocialIdentityNotFound) {
		t.Fatalf("someone else's identity: err = %v", err)
	}
	if err := f.client.User.UpdateOneID(u.ID).SetPasswordHash("x").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.s.UnlinkSocialIdentity(ctx, u.ID, tiktok, "", ""); err != nil {
		t.Fatalf("unlink with a password: %v", err)
	}
}
