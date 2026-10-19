package handlers

import "testing"

func TestPortalResetDenial(t *testing.T) {
	pending := map[string]any{"must_change_password": true}
	cases := []struct {
		name    string
		roles   []string
		profile map[string]any
		want    string
	}{
		{"unclaimed student", []string{"student"}, pending, ""},
		{"unclaimed parent", []string{"parent"}, pending, ""},
		{"student and parent", []string{"student", "parent"}, pending, ""},
		{"no roles", nil, pending, "not_a_member"},
		{"staff role", []string{"admin"}, pending, "not_a_portal_account"},
		{"student who is also staff", []string{"student", "admin"}, pending, "not_a_portal_account"},
		{"owner", []string{"owner"}, pending, "not_a_portal_account"},
		{"claimed account", []string{"student"}, map[string]any{"must_change_password": false}, "already_claimed"},
		{"flag missing", []string{"parent"}, map[string]any{}, "already_claimed"},
		{"nil profile", []string{"parent"}, nil, "already_claimed"},
		{"flag of the wrong type", []string{"parent"}, map[string]any{"must_change_password": "true"}, "already_claimed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := portalResetDenial(c.roles, c.profile); got != c.want {
				t.Fatalf("portalResetDenial(%v) = %q, want %q", c.roles, got, c.want)
			}
		})
	}
}
