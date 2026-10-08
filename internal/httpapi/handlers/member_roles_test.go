package handlers

import (
	"reflect"
	"testing"
)

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
