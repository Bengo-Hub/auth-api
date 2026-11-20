package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
	"github.com/bengobox/auth-api/internal/oauth/state"
	googleprovider "github.com/bengobox/auth-api/internal/providers/google"
	tiktokprovider "github.com/bengobox/auth-api/internal/providers/tiktok"
)

type fakeTikTok struct{ profile tiktokprovider.Profile }

func (f *fakeTikTok) AuthCodeURL(_ context.Context, st string) (string, error) {
	return "https://www.tiktok.com/v2/auth/authorize/?state=" + st, nil
}

func (f *fakeTikTok) Exchange(_ context.Context, code string) (*oauth2.Token, error) {
	if code != "good-code" {
		return nil, errors.New("bad code")
	}
	return (&oauth2.Token{AccessToken: "act"}).WithExtra(map[string]any{"open_id": f.profile.OpenID, "scope": "user.info.basic"}), nil
}

func (f *fakeTikTok) FetchProfile(_ context.Context, _ *oauth2.Token) (*tiktokprovider.Profile, error) {
	p := f.profile
	return &p, nil
}

func TestTikTokPlaceholderEmail(t *testing.T) {
	a, b := TikTokPlaceholderEmail("open-a"), TikTokPlaceholderEmail("open-b")
	if a == b || a != TikTokPlaceholderEmail("open-a") {
		t.Fatal("placeholder must be stable per open_id and differ between people")
	}
	if !IsPlaceholderEmail(a) || !strings.HasPrefix(a, "tiktok-") {
		t.Fatalf("%s must be a replaceable placeholder", a)
	}
}

func TestTikTokNotConfigured(t *testing.T) {
	s := &Service{}
	if _, err := s.StartTikTokOAuth(context.Background(), OAuthStartInput{}); !errors.Is(err, ErrProviderNotEnabled) {
		t.Fatalf("start err = %v", err)
	}
	if _, err := s.CompleteTikTokOAuth(context.Background(), OAuthCallbackInput{Code: "c", State: "s"}); !errors.Is(err, ErrProviderNotEnabled) {
		t.Fatalf("complete err = %v", err)
	}
}

func TestTikTokSignIn(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	openID := "open-" + uuid.NewString()
	fake := &fakeTikTok{profile: tiktokprovider.Profile{OpenID: openID, UnionID: "union-1", DisplayName: "Wanjiku", AvatarURL: "https://p16.example/a.jpg"}}
	s.tiktok = fake

	platform, err := client.Tenant.Query().Where(tenant.SlugEQ(platformTenantSlug)).Only(ctx)
	if err != nil {
		platform, err = client.Tenant.Create().SetName("Codevertex").SetSlug(platformTenantSlug).SetStatus("active").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	staff, err := client.Tenant.Create().SetName("Staff Org").SetSlug("staff-" + uuid.NewString()[:8]).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stateFor := func(slug string) string {
		st, err := state.Encode(s.cfg.Security.OAuthStateSecret, state.Payload{TenantSlug: slug, Flow: "login", Nonce: randomNonce()}, oauthStateTTL)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	t.Run("start carries a signed state", func(t *testing.T) {
		u, err := s.StartTikTokOAuth(ctx, OAuthStartInput{TenantSlug: platform.Slug})
		if err != nil {
			t.Fatal(err)
		}
		st := u[strings.Index(u, "state=")+len("state="):]
		p, err := state.Decode(s.cfg.Security.OAuthStateSecret, st)
		if err != nil || p.TenantSlug != platform.Slug {
			t.Fatalf("state %+v err %v", p, err)
		}
	})

	t.Run("an MFA challenge is not accepted as a provider state", func(t *testing.T) {
		st, _ := state.Encode(s.cfg.Security.OAuthStateSecret, state.Payload{TenantSlug: platform.Slug, Purpose: state.PurposeSocialMFA}, oauthStateTTL)
		if _, err := s.CompleteTikTokOAuth(ctx, OAuthCallbackInput{Code: "good-code", State: st}); !errors.Is(err, ErrOAuthStateInvalid) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a new person in a staff tenant is refused and leaves no account", func(t *testing.T) {
		_, err := s.CompleteTikTokOAuth(ctx, OAuthCallbackInput{Code: "good-code", State: stateFor(staff.Slug)})
		if !errors.Is(err, ErrTenantMembershipRequired) {
			t.Fatalf("err = %v", err)
		}
		if n, _ := client.User.Query().Where(user.EmailEQ(TikTokPlaceholderEmail(openID))).Count(ctx); n != 0 {
			t.Fatalf("refused sign-up left %d account(s)", n)
		}
	})

	var firstID uuid.UUID
	t.Run("a new person self-registers on the platform with a placeholder email", func(t *testing.T) {
		res, err := s.CompleteTikTokOAuth(ctx, OAuthCallbackInput{Code: "good-code", State: stateFor(platform.Slug)})
		if err != nil {
			t.Fatal(err)
		}
		if res.AccessToken == "" || res.User == nil {
			t.Fatalf("no session issued: %+v", res)
		}
		firstID = res.User.ID
		if !IsPlaceholderEmail(res.User.Email) || res.User.EmailVerified {
			t.Fatalf("email %q verified=%v, want an unverified placeholder", res.User.Email, res.User.EmailVerified)
		}
		if profileStr(res.User.Profile, "name") != "Wanjiku" {
			t.Fatalf("profile = %v", res.User.Profile)
		}
		ident, err := client.UserIdentity.Query().Where(useridentity.ProviderEQ("tiktok"), useridentity.ProviderSubjectEQ(openID)).Only(ctx)
		if err != nil {
			t.Fatalf("identity: %v", err)
		}
		if ident.Profile["union_id"] != "union-1" || ident.AccessToken != "" {
			t.Fatalf("identity profile %v, token kept %v", ident.Profile, ident.AccessToken != "")
		}
	})

	t.Run("the same TikTok account signs in to the same user again", func(t *testing.T) {
		fake.profile.DisplayName = "Wanjiku M"
		res, err := s.CompleteTikTokOAuth(ctx, OAuthCallbackInput{Code: "good-code", State: stateFor(platform.Slug)})
		if err != nil {
			t.Fatal(err)
		}
		if res.User.ID != firstID {
			t.Fatalf("second sign-in made a new account %s, want %s", res.User.ID, firstID)
		}
		if n, _ := client.UserIdentity.Query().Where(useridentity.ProviderEQ("tiktok"), useridentity.ProviderSubjectEQ(openID)).Count(ctx); n != 1 {
			t.Fatalf("identities = %d", n)
		}
	})

	t.Run("an existing member of a staff tenant gets in", func(t *testing.T) {
		if _, err := client.TenantMembership.Create().SetUserID(firstID).SetTenantID(staff.ID).SetRoles([]string{"member"}).Save(ctx); err != nil {
			t.Fatal(err)
		}
		res, err := s.CompleteTikTokOAuth(ctx, OAuthCallbackInput{Code: "good-code", State: stateFor(staff.Slug)})
		if err != nil {
			t.Fatal(err)
		}
		if res.User.ID != firstID || res.Tenant.ID != staff.ID {
			t.Fatalf("signed in as %s to %s", res.User.ID, res.Tenant.Slug)
		}
	})

	t.Run("a bad code fails without a session", func(t *testing.T) {
		if _, err := s.CompleteTikTokOAuth(ctx, OAuthCallbackInput{Code: "bad", State: stateFor(platform.Slug)}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

// GitHub and Microsoft identities were saved under "google", so the next sign-in never found
// them and failed on the unique (provider, subject) index.
func TestCreateIdentityKeepsProvider(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	u, err := client.User.Create().SetEmail("gh-" + uuid.NewString()[:8] + "@example.org").SetStatus(UserStatusActive).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.createIdentity(ctx, githubProviderName, u.ID, &googleprovider.Profile{Subject: "4242", Email: u.Email}, nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.UserIdentity.Query().Where(useridentity.ProviderEQ(githubProviderName), useridentity.ProviderSubjectEQ("4242")).Count(ctx); n != 1 {
		t.Fatalf("github identity not found under its own provider (n=%d)", n)
	}
}
