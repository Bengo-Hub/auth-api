package handlers

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
)

// marketflow_reviewer is the least-privilege role for the Meta App Review account. It is a
// MarketFlow service role: assignable per tenant like marketflow_member, and never admin tier,
// so holding it can never make anyone an organisation admin, a billing contact or a platform owner.
func TestMarketflowReviewerIsNeverAdminTier(t *testing.T) {
	roles := []string{"marketflow_reviewer"}
	if isPlatformAdminRole(roles) {
		t.Error("isPlatformAdminRole: reviewer must not be admin tier")
	}
	if isTenantAdminRole("marketflow_reviewer") || hasTenantAdminRole(roles) {
		t.Error("tenant admin: reviewer must not be a tenant admin")
	}
	if isAdminOrManagerRole(roles) {
		t.Error("isAdminOrManagerRole: reviewer must not be admin or manager tier")
	}
	if isBillingAdminRole(roles) {
		t.Error("isBillingAdminRole: reviewer must not be a billing contact")
	}
}

// A tenant admin may assign it once the catalogue knows it, and a service may add it like any other
// service role.
func TestMarketflowReviewerIsAssignable(t *testing.T) {
	known := map[string]bool{"marketflow_admin": true, "marketflow_member": true, "marketflow_reviewer": true}
	if got := refusedRoles([]string{"marketflow_reviewer"}, nil, known); got != nil {
		t.Fatalf("tenant admin grant refused: %v", got)
	}
	if got := refusedRoles([]string{"marketflow_reviewer"}, nil, map[string]bool{}); !reflect.DeepEqual(got, []string{"marketflow_reviewer"}) {
		t.Fatalf("unknown to the catalogue it is refused, got %v", got)
	}

	svc := httptest.NewRequest(http.MethodPost, "/", nil)
	svc = svc.WithContext(authmiddleware.ContextWithClaims(svc.Context(), &token.Claims{IsPlatformOwner: true}))
	if serviceAdminGrantRefused(svc, []string{"marketflow_reviewer"}) {
		t.Error("a service may add the reviewer role")
	}
}
