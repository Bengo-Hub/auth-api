package auth

import "testing"

func TestUserCanSignIn(t *testing.T) {
	cases := map[string]bool{
		"":                        true, // older rows without a status
		UserStatusActive:          true,
		UserStatusPendingDeletion: true, // must be able to sign in to cancel the deletion
		UserStatusSuspended:       false,
		UserStatusDeactivated:     false,
		UserStatusInactive:        false,
		UserStatusDeleted:         false,
		"something_new":           false, // unknown states fail closed
	}
	for status, want := range cases {
		if got := UserCanSignIn(status); got != want {
			t.Errorf("UserCanSignIn(%q) = %v, want %v", status, got, want)
		}
	}
}
