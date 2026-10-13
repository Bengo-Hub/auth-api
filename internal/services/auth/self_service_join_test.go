package auth

import (
	"context"
	"errors"
	"testing"
)

func TestIsSelfServiceRole(t *testing.T) {
	for _, role := range []string{"member", "customer", "student", "parent", "driver", " customer "} {
		if !IsSelfServiceRole(role) {
			t.Errorf("%q should be self-service", role)
		}
	}
	for _, role := range []string{"admin", "superuser", "owner", "manager", "cashier", "digitika_admin", ""} {
		if IsSelfServiceRole(role) {
			t.Errorf("%q must not be self-service", role)
		}
	}
}

// A public registration into an existing tenant used to accept any role, so anyone could join
// any organisation as its admin. It must now be refused before anything is written.
func TestRegisterRejectsStaffRoleOnJoin(t *testing.T) {
	s := &Service{}
	for _, role := range []string{"admin", "superuser", "manager"} {
		_, err := s.Register(context.Background(), RegisterInput{
			Email:      "someone@example.com",
			Password:   "Str0ng!Passw0rd",
			TenantSlug: "urban-loft",
			OrgAction:  "join_existing",
			Role:       role,
		})
		if !errors.Is(err, ErrRoleNotAllowed) {
			t.Errorf("role %q: got %v, want ErrRoleNotAllowed", role, err)
		}
	}
}
