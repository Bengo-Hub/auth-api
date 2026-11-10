package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
)

// Security audit 2026-11-10 (H4), owner decisions: an existing account added to a team joins
// only after it accepts; new accounts, signed-in platform owners and portal adds by phone join
// at once.
func TestNeedsMemberConsent(t *testing.T) {
	if !needsMemberConsent(false, false, false) {
		t.Error("an existing account added to a team needs consent")
	}
	if needsMemberConsent(true, false, false) || needsMemberConsent(false, true, false) || needsMemberConsent(false, false, true) {
		t.Error("new accounts, platform owners and portal adds join at once")
	}
	if !isPortalAdd("+254700000000", []string{"member"}) || !isPortalAdd("+254700000000", []string{"customer", "member"}) {
		t.Error("a phone add with portal roles is a portal add")
	}
	if isPortalAdd("", []string{"member"}) || isPortalAdd("+254700000000", []string{"admin"}) || isPortalAdd("+254700000000", []string{"member", "cashier"}) {
		t.Error("an email add, or any staff role, is not a portal add")
	}
}

func TestServiceClaimsAreNotInteractivePlatformOwner(t *testing.T) {
	svc := httptest.NewRequest(http.MethodPost, "/", nil)
	svc = svc.WithContext(authmiddleware.ContextWithClaims(svc.Context(), &token.Claims{IsPlatformOwner: true}))
	if interactivePlatformOwner(svc) {
		t.Fatal("the S2S shim (no subject) is not a signed-in platform owner")
	}
	po := &token.Claims{IsPlatformOwner: true}
	po.Subject = uuid.NewString()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if !interactivePlatformOwner(req.WithContext(authmiddleware.ContextWithClaims(req.Context(), po))) {
		t.Fatal("a signed-in platform owner")
	}
}

func TestAcceptAndDeclineInvitation(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	shop := client.Tenant.Create().SetName("Shop").SetSlug("shop-" + sfx).SetStatus("active").SaveX(ctx)
	other := client.Tenant.Create().SetName("Other").SetSlug("other-" + sfx).SetStatus("active").SaveX(ctx)
	u := client.User.Create().SetEmail("p-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(shop.ID).SetRoles([]string{"cashier"}).SetStatus(memberStatusInvited).SaveX(ctx)
	client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(other.ID).SetRoles([]string{"cashier"}).SetStatus(memberStatusInvited).SaveX(ctx)
	h := &AdminHandler{ent: client, logger: zap.NewNop()}

	call := func(fn http.HandlerFunc, who uuid.UUID, tenant uuid.UUID) int {
		c := &token.Claims{}
		c.Subject = who.String()
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("tenant_id", tenant.String())
		r = r.WithContext(context.WithValue(authmiddleware.ContextWithClaims(r.Context(), c), chi.RouteCtxKey, rc))
		w := httptest.NewRecorder()
		fn(w, r)
		return w.Code
	}
	if code := call(h.AcceptInvitation, uuid.New(), shop.ID); code != http.StatusNotFound {
		t.Fatalf("someone else cannot accept: %d", code)
	}
	if code := call(h.AcceptInvitation, u.ID, shop.ID); code != http.StatusOK {
		t.Fatalf("accept: %d", code)
	}
	if s := client.TenantMembership.Query().Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(shop.ID)).OnlyX(ctx).Status; s != "active" {
		t.Fatalf("after accept: %s", s)
	}
	if code := call(h.DeclineInvitation, u.ID, other.ID); code != http.StatusOK {
		t.Fatalf("decline: %d", code)
	}
	if n := client.TenantMembership.Query().Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(other.ID)).CountX(ctx); n != 0 {
		t.Fatal("a declined invitation leaves no membership")
	}
}

// Security audit 2026-11-11: services add members through the S2S route with platform claims, so
// role checks were skipped; an unguarded service endpoint (inventory, treasury, projects
// POST /users) let any member make themselves, or anyone, admin of the organisation, and in the
// codevertex tenant that makes a platform owner. A service add never grants an admin-tier role;
// those are given by a signed-in admin.
func TestServiceAddCannotGrantAdminRoles(t *testing.T) {
	svc := httptest.NewRequest(http.MethodPost, "/", nil)
	svc = svc.WithContext(authmiddleware.ContextWithClaims(svc.Context(), &token.Claims{IsPlatformOwner: true}))
	for _, roles := range [][]string{{"admin"}, {"cashier", "superuser"}, {"owner"}} {
		if !serviceAdminGrantRefused(svc, roles) {
			t.Errorf("service add of %v must be refused", roles)
		}
	}
	if serviceAdminGrantRefused(svc, []string{"cashier", "store_manager", "marketflow_admin"}) {
		t.Error("service roles are fine")
	}
	po := &token.Claims{IsPlatformOwner: true}
	po.Subject = uuid.NewString()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if serviceAdminGrantRefused(req.WithContext(authmiddleware.ContextWithClaims(req.Context(), po)), []string{"admin"}) {
		t.Error("a signed-in platform owner may grant admin")
	}
}
