package auth

import (
	"reflect"
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
)

func TestUsesTenantPaths(t *testing.T) {
	cases := []struct {
		meta map[string]any
		want bool
	}{
		{nil, true},
		{map[string]any{}, true},
		{map[string]any{TenantPathsKey: true}, true},
		{map[string]any{TenantPathsKey: "false"}, true},
		{map[string]any{TenantPathsKey: false}, false},
	}
	for _, c := range cases {
		if got := UsesTenantPaths(&ent.OAuthClient{Metadata: c.meta}); got != c.want {
			t.Fatalf("metadata %v: got %v, want %v", c.meta, got, c.want)
		}
	}
}

func TestNextRedirectURIsRename(t *testing.T) {
	current := []string{
		"https://pos.example.com/auth/callback",
		"https://pos.example.com/old-shop/auth/callback",
		"http://localhost:3000/old-shop/auth/callback",
		"https://pos.example.com/other/auth/callback",
	}
	got, changed := nextRedirectURIs(current, "new-shop", "old-shop", true)
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
	if again, changed := nextRedirectURIs(got, "new-shop", "old-shop", true); changed || !reflect.DeepEqual(again, got) {
		t.Fatalf("not idempotent: changed=%v %v", changed, again)
	}
}

func TestNextRedirectURIsAppendKeepsExisting(t *testing.T) {
	current := []string{"https://pos.example.com/auth/callback", "https://pos.example.com/shop/auth/callback"}
	got, changed := nextRedirectURIs(current, "shop", "", true)
	if !changed || len(got) != 3 || got[2] != "http://localhost:3000/shop/auth/callback" {
		t.Fatalf("append: changed=%v got=%v", changed, got)
	}
}

func TestNextRedirectURIsSkipsClientsWithoutProductionHost(t *testing.T) {
	current := []string{"http://localhost:3000/auth/callback"}
	if got, changed := nextRedirectURIs(current, "shop", "old", true); changed || !reflect.DeepEqual(got, current) {
		t.Fatalf("local-only client must be untouched: changed=%v %v", changed, got)
	}
}

func TestServesUseCases(t *testing.T) {
	none := map[string]any{}
	cases := []struct {
		name   string
		client string
		meta   map[string]any
		uc     []string
		want   bool
	}{
		{"platform app serves all", "treasury-ui", none, []string{"property"}, true},
		{"matching use case", "pos-ui", none, []string{"retail"}, true},
		{"alias matches its use case", "pos-ui", none, []string{"grocery"}, true},
		{"no matching use case", "pos-ui", none, []string{"property"}, false},
		{"tenant without use cases served everywhere", "pos-ui", none, nil, true},
		{"single-domain client serves nobody", "hadia-ui", map[string]any{TenantPathsKey: false}, []string{"gift_registry"}, false},
	}
	for _, c := range cases {
		if got := ServesUseCases(c.client, c.meta, c.uc); got != c.want {
			t.Fatalf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNextRedirectURIsDropsUnservedTenant(t *testing.T) {
	current := []string{
		"https://pos.example.com/auth/callback",
		"https://pos.example.com/estate/auth/callback",
		"http://localhost:3000/estate/auth/callback",
	}
	got, changed := nextRedirectURIs(current, "estate", "", false)
	if !changed || !reflect.DeepEqual(got, []string{"https://pos.example.com/auth/callback"}) {
		t.Fatalf("unserved tenant paths must be removed: changed=%v %v", changed, got)
	}
}
