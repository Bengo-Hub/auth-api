package handlers

import (
	"reflect"
	"testing"
)

// A tenant admin grants only roles auth knows, and never a super role. What the member already holds
// stays, including a service's own role and a super role granted by the platform.
func TestRefusedRoles(t *testing.T) {
	known := map[string]bool{"cashier": true, "manager": true, "admin": true, "superuser": true}
	cases := []struct {
		name                string
		requested, existing []string
		want                []string
	}{
		{"catalogue roles pass", []string{"cashier", "manager"}, nil, nil},
		{"admin can be granted, the plan limit applies separately", []string{"admin"}, []string{"cashier"}, nil},
		{"super role refused", []string{"superuser"}, []string{"admin"}, []string{"superuser"}},
		{"made-up role refused", []string{"platform_owner"}, nil, []string{"platform_owner"}},
		{"platform-only roles refused", []string{"developer", "customer", "member"}, nil, []string{"developer", "customer", "member"}},
		{"held platform-only role stays", []string{"member"}, []string{"member"}, nil},
		{"held super role stays", []string{"superuser", "cashier"}, []string{"superuser"}, nil},
		{"held service role stays", []string{"maskani_owner"}, []string{"maskani_owner"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := refusedRoles(c.requested, c.existing, known); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Only staff are placed at the default outlet: a customer is not tied to a branch.
func TestHasStaffRole(t *testing.T) {
	for _, c := range []struct {
		roles []string
		want  bool
	}{
		{[]string{"cashier"}, true},
		{[]string{"customer", "manager"}, true},
		{[]string{"customer"}, false},
		{[]string{"member"}, false},
		{nil, false},
	} {
		if got := hasStaffRole(c.roles); got != c.want {
			t.Errorf("%v: got %v, want %v", c.roles, got, c.want)
		}
	}
}

// A portal invite for someone who is already staff must add the portal role, never drop staff roles.
func TestMergeRoleListsKeepsExistingRoles(t *testing.T) {
	got := mergeRoleLists([]string{"admin", "manager"}, []string{"maskani_owner", "admin", ""})
	want := []string{"admin", "manager", "maskani_owner"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := mergeRoleLists(nil, []string{"maskani_owner"}); !reflect.DeepEqual(got, []string{"maskani_owner"}) {
		t.Fatalf("empty current: got %v", got)
	}
}
