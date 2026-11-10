package handlers

import (
	"reflect"
	"testing"
)

// Security audit 2026-11-10 (C2): the scope a user asked for at /authorize was copied into the
// access token, and the admin gates accept "admin" / "auth.admin" scopes as platform authority,
// so any signed-in user could mint an admin token. Sign-in tokens never carry reserved scopes.
func TestUserTokenScopesDropReservedPlatformScopes(t *testing.T) {
	got := userTokenScopes("openid profile admin auth.admin offline_access " + InternalServiceKeyScope + " email")
	want := []string{"openid", "profile", "offline_access", "email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := userTokenScopesFromList([]string{"openid", "ADMIN", "Auth.Admin"}); !reflect.DeepEqual(got, []string{"openid"}) {
		t.Fatalf("case-insensitive: got %v", got)
	}
}
