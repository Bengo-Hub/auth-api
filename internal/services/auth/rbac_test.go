package auth

import "testing"

// Regression coverage for the 2026-08-18 platform-admin gating fix: a
// non-admin role (e.g. a custom "COO" role) inside the platform tenant must
// never be treated as a platform admin — only admin/superuser qualifies.
func TestIsPlatformAdminRole(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"admin qualifies", []string{"admin"}, true},
		{"superuser qualifies", []string{"superuser"}, true},
		{"admin among other roles qualifies", []string{"member", "admin"}, true},
		{"member alone does not qualify", []string{"member"}, false},
		{"custom COO role does not qualify", []string{"COO"}, false},
		{"owner alone does not qualify (not admin/superuser)", []string{"owner"}, false},
		{"empty roles does not qualify", []string{}, false},
		{"nil roles does not qualify", nil, false},
		{"case-sensitive: Admin (capitalized) does not qualify", []string{"Admin"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPlatformAdminRole(c.roles); got != c.want {
				t.Errorf("isPlatformAdminRole(%v) = %v, want %v", c.roles, got, c.want)
			}
		})
	}
}
