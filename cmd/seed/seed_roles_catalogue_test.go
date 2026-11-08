package main

import "testing"

// Hospital roles carry the hospital scope, so a hospital tenant's role editor offers them before any
// member holds one (they used to fall to platform). Every role in the catalogue has a scope.
func TestRoleScopes(t *testing.T) {
	for code, want := range map[string]string{
		"doctor":        "hospital",
		"nurse":         "hospital",
		"records_clerk": "hospital",
		"pharmacist":    "pos",
		"hadia_admin":   "hadia",
	} {
		if got := roleScope(code); got != want {
			t.Errorf("roleScope(%q) = %q, want %q", code, got, want)
		}
	}
	for code := range rolePerms {
		if roleScope(code) == "" {
			t.Errorf("role %q has no scope", code)
		}
	}
}
