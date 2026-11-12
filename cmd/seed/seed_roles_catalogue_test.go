package main

import (
	"strings"
	"testing"
)

// Hospital roles carry the hospital scope, so a hospital tenant's role editor offers them before any
// member holds one (they used to fall to platform). Every role in the catalogue has a scope.
func TestRoleScopes(t *testing.T) {
	for code, want := range map[string]string{
		"doctor":              "hospital",
		"nurse":               "hospital",
		"records_clerk":       "hospital",
		"pharmacist":          "pos",
		"hadia_admin":         "hadia",
		"marketflow_admin":    "marketflow",
		"marketflow_member":   "marketflow",
		"marketflow_reviewer": "marketflow",
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

// MarketFlow's SSO roles are seeded under the names and scope marketflow-api pushes, so a reseed and
// the push agree, and the reviewer role can be assigned before the first push. They carry auth.*
// self-service only (never the all-permissions set), like the other service roles.
func TestMarketflowRolesSeeded(t *testing.T) {
	for code, name := range map[string]string{
		"marketflow_admin":    "MarketFlow admin",
		"marketflow_member":   "MarketFlow member",
		"marketflow_reviewer": "MarketFlow app reviewer",
	} {
		perms, ok := rolePerms[code]
		if !ok {
			t.Errorf("%s is not in the seeded catalogue", code)
			continue
		}
		if len(perms) == 0 {
			t.Errorf("%s would get every permission (empty set means all)", code)
		}
		for _, p := range perms {
			if !strings.HasPrefix(p, "auth.profile.") && !strings.HasPrefix(p, "auth.preferences.") && !strings.HasPrefix(p, "auth.notifications.") {
				t.Errorf("%s: %s is more than self-service", code, p)
			}
		}
		if got := roleDisplayName(code); got != name {
			t.Errorf("roleDisplayName(%q) = %q, want %q", code, got, name)
		}
		if wildcardRoles[code] || platformSystemRoles[code] {
			t.Errorf("%s must be a plain service role", code)
		}
	}
}
