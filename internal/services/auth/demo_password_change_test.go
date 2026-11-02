package auth

import (
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/token"
)

func TestWithoutDemoPasswordChange(t *testing.T) {
	pending := func() *ent.User {
		return &ent.User{Email: "rider@demo.example", Profile: map[string]any{"name": "Demo Rider", "must_change_password": true}}
	}

	t.Run("demo session hides the flag and leaves the stored profile alone", func(t *testing.T) {
		u := pending()
		got := withoutDemoPasswordChange(u, token.AccessTokenInput{IsDemo: true})
		if _, ok := got.Profile["must_change_password"]; ok {
			t.Fatal("demo session still sees must_change_password")
		}
		if got.Profile["name"] != "Demo Rider" || got.Email != u.Email {
			t.Fatal("other profile fields or the user itself were lost")
		}
		if v, _ := u.Profile["must_change_password"].(bool); !v {
			t.Fatal("the original profile was modified")
		}
	})

	t.Run("platform owner on the demo tenant keeps it", func(t *testing.T) {
		u := pending()
		if got := withoutDemoPasswordChange(u, token.AccessTokenInput{IsDemo: true, IsPlatformOwner: true}); got != u {
			t.Fatal("platform owner session should be unchanged")
		}
	})

	t.Run("non-demo tenant keeps it", func(t *testing.T) {
		u := pending()
		if got := withoutDemoPasswordChange(u, token.AccessTokenInput{}); got != u {
			t.Fatal("non-demo session should be unchanged")
		}
	})

	t.Run("no flag or no user is a no-op", func(t *testing.T) {
		u := &ent.User{Profile: map[string]any{"name": "x"}}
		if got := withoutDemoPasswordChange(u, token.AccessTokenInput{IsDemo: true}); got != u {
			t.Fatal("user without the flag should be returned as is")
		}
		if withoutDemoPasswordChange(nil, token.AccessTokenInput{IsDemo: true}) != nil {
			t.Fatal("nil user should stay nil")
		}
	})
}
