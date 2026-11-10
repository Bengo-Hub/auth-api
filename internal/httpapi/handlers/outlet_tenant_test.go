package handlers

import (
	"testing"

	"github.com/bengobox/auth-api/internal/token"
	"github.com/google/uuid"
)

// Security audit 2026-11-10 (H1): outlet create/update/archive checked only for an admin role,
// never that the {slug} tenant is the caller's own, so an admin of one tenant could change
// another tenant's outlets.
func TestRequireTenantAdminOfIsTenantScoped(t *testing.T) {
	h := &OutletHandler{}
	own, other := uuid.New(), uuid.New()

	admin := reqWithClaims(&token.Claims{TenantID: own.String(), Roles: []string{"admin"}})
	if !h.requireTenantAdminOf(admin, own) {
		t.Fatal("an admin manages their own tenant's outlets")
	}
	if h.requireTenantAdminOf(admin, other) {
		t.Fatal("an admin of one tenant must not manage another tenant's outlets")
	}
	member := reqWithClaims(&token.Claims{TenantID: own.String(), Roles: []string{"member"}})
	if h.requireTenantAdminOf(member, own) {
		t.Fatal("a member is not a tenant admin")
	}
	po := reqWithClaims(&token.Claims{TenantID: uuid.NewString(), IsPlatformOwner: true})
	if !h.requireTenantAdminOf(po, other) {
		t.Fatal("platform owners manage any tenant's outlets")
	}
	if h.requireTenantAdminOf(reqWithClaims(nil), own) {
		t.Fatal("no claims, no access")
	}
}
