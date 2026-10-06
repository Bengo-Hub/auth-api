package auth

import "errors"

// User.status values. "active" signs in normally. "pending_deletion" also signs in, so the person
// can still cancel a deletion they asked for during its 30-day wait. Every other status is blocked.
const (
	UserStatusActive          = "active"
	UserStatusPendingDeletion = "pending_deletion"
	UserStatusSuspended       = "suspended"
	UserStatusDeactivated     = "deactivated"
	UserStatusInactive        = "inactive"
	UserStatusDeleted         = "deleted"
)

// ErrAccountDisabled is returned after a correct password when the account may not sign in
// (suspended, deactivated, inactive or soft-deleted). It is only checked after the password, so
// it never tells a stranger whether an account exists or what state it is in.
var ErrAccountDisabled = errors.New("account is disabled")

// UserCanSignIn reports whether a user with this status may get new sessions or tokens. An empty
// status is treated as active: older rows were created before status was always set.
func UserCanSignIn(status string) bool {
	switch status {
	case "", UserStatusActive, UserStatusPendingDeletion:
		return true
	default:
		return false
	}
}
