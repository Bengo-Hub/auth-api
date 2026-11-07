package auth

import "testing"

// A tenant's editor offers its own use case's roles and the tenant-wide ones, not the whole catalogue.
func TestRoleFitsTenant(t *testing.T) {
	scopes := roleScopesFor("gift_registry", []string{"gift_registry"})
	for _, c := range []struct {
		code, scope string
		want        bool
	}{
		{"hadia_admin", "hadia", true},
		{"admin", "platform", true},
		{"superuser", "platform", true},
		{"barista", "pos", false},
		{"digitika_admin", "digitika", false},
		{"doctor", "platform", false},
		{"a", "pos", false},
	} {
		if got := roleFitsTenant(c.code, c.scope, scopes); got != c.want {
			t.Errorf("%s (%s): %v, want %v", c.code, c.scope, got, c.want)
		}
	}
}
