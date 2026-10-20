package auth

import (
	"reflect"
	"testing"
)

func TestNextRedirectURIsRename(t *testing.T) {
	current := []string{
		"https://pos.example.com/auth/callback",
		"https://pos.example.com/old-shop/auth/callback",
		"http://localhost:3000/old-shop/auth/callback",
		"https://pos.example.com/other/auth/callback",
	}
	got, changed := nextRedirectURIs(current, "new-shop", "old-shop")
	want := []string{
		"https://pos.example.com/auth/callback",
		"https://pos.example.com/other/auth/callback",
		"https://pos.example.com/new-shop/auth/callback",
		"http://localhost:3000/new-shop/auth/callback",
	}
	if !changed || !reflect.DeepEqual(got, want) {
		t.Fatalf("rename: changed=%v got=%v", changed, got)
	}
	// Running it again changes nothing.
	if again, changed := nextRedirectURIs(got, "new-shop", "old-shop"); changed || !reflect.DeepEqual(again, got) {
		t.Fatalf("not idempotent: changed=%v %v", changed, again)
	}
}

func TestNextRedirectURIsAppendKeepsExisting(t *testing.T) {
	current := []string{"https://pos.example.com/auth/callback", "https://pos.example.com/shop/auth/callback"}
	got, changed := nextRedirectURIs(current, "shop", "")
	if !changed || len(got) != 3 || got[2] != "http://localhost:3000/shop/auth/callback" {
		t.Fatalf("append: changed=%v got=%v", changed, got)
	}
}

func TestNextRedirectURIsSkipsClientsWithoutProductionHost(t *testing.T) {
	current := []string{"http://localhost:3000/auth/callback"}
	if got, changed := nextRedirectURIs(current, "shop", "old"); changed || !reflect.DeepEqual(got, current) {
		t.Fatalf("local-only client must be untouched: changed=%v %v", changed, got)
	}
}
