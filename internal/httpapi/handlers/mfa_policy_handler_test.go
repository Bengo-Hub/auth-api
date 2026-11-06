package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/auditlog"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/token"
)

// policyRequest builds a request carrying claims and, when tenantID is set, the {tenant_id} param.
func policyRequest(method, body string, claims *token.Claims, tenantID string) *http.Request {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	ctx := req.Context()
	if claims != nil {
		ctx = authmiddleware.ContextWithClaims(ctx, claims)
	}
	if tenantID != "" {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("tenant_id", tenantID)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
	}
	return req.WithContext(ctx)
}

// Only a platform owner reads or edits an MFA policy: a tenant's own admin, any other member and
// an admin-scoped service token are refused before anything is read.
func TestMFAPolicyRoutesArePlatformOwnerOnly(t *testing.T) {
	h := &RBACHandler{logger: zap.NewNop()} // no service: a refusal must not reach it
	tenantID := uuid.NewString()
	callers := map[string]*token.Claims{
		"anonymous":            nil,
		"tenant admin":         {TenantID: tenantID, Roles: []string{"admin", "superuser"}},
		"hadia staff":          {TenantID: tenantID, Roles: []string{"hadia_admin"}},
		"admin-scoped service": {Scope: []string{"admin", "auth.admin"}},
	}
	routes := map[string]struct {
		fn     http.HandlerFunc
		method string
		tenant string
	}{
		"get platform":   {h.GetPlatformMFAPolicy, http.MethodGet, ""},
		"patch platform": {h.UpdatePlatformMFAPolicy, http.MethodPatch, ""},
		"get tenant":     {h.GetTenantMFAPolicy, http.MethodGet, tenantID},
		"patch tenant":   {h.UpdateTenantMFAPolicy, http.MethodPatch, tenantID},
	}
	for who, claims := range callers {
		for name, rt := range routes {
			rec := httptest.NewRecorder()
			rt.fn(rec, policyRequest(rt.method, `{"required_roles":[],"all_accounts":true}`, claims, rt.tenant))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s on %s: %d, want 403", who, name, rec.Code)
			}
		}
	}
}

func TestMFAPolicyRoutes(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	svc := auth.New(auth.Dependencies{EntClient: client, Logger: zap.NewNop(), Auditor: audit.New(client, zap.NewNop())})
	h := &RBACHandler{svc: svc, logger: zap.NewNop()}
	owner := &token.Claims{IsPlatformOwner: true}
	owner.Subject = uuid.NewString()

	client.Tenant.Create().SetName("Codevertex").SetSlug("codevertex").SaveX(ctx)
	hadia := client.Tenant.Create().SetName("Hadia").SetSlug("hadia-" + uuid.NewString()[:8]).SaveX(ctx)

	do := func(fn http.HandlerFunc, method, body, tenantID string) (int, auth.MFAPolicyView) {
		rec := httptest.NewRecorder()
		fn(rec, policyRequest(method, body, owner, tenantID))
		var view auth.MFAPolicyView
		_ = json.Unmarshal(rec.Body.Bytes(), &view)
		return rec.Code, view
	}

	if code, view := do(h.GetPlatformMFAPolicy, http.MethodGet, "", ""); code != http.StatusOK || !view.Policy.IsEmpty() {
		t.Fatalf("platform default starts empty: %d %+v", code, view)
	}
	if code, view := do(h.UpdatePlatformMFAPolicy, http.MethodPatch, `{"required_roles":["admin"," admin "],"all_accounts":false}`, ""); code != http.StatusOK ||
		strings.Join(view.Policy.RequiredRoles, ",") != "admin" {
		t.Fatalf("set platform default: %d %+v", code, view)
	}

	code, view := do(h.GetTenantMFAPolicy, http.MethodGet, "", hadia.ID.String())
	if code != http.StatusOK || !view.Inherited || strings.Join(view.Effective.RequiredRoles, ",") != "admin" {
		t.Fatalf("a tenant without its own policy inherits: %d %+v", code, view)
	}
	code, view = do(h.UpdateTenantMFAPolicy, http.MethodPatch, `{"required_roles":["hadia_admin","hadia_finance","hadia_support"]}`, hadia.ID.String())
	if code != http.StatusOK || view.Inherited || strings.Join(view.Effective.RequiredRoles, ",") != "hadia_admin,hadia_finance,hadia_support" {
		t.Fatalf("set tenant policy: %d %+v", code, view)
	}
	for _, r := range []string{"hadia_admin", "hadia_finance", "hadia_support"} {
		if !strings.Contains(strings.Join(view.AvailableRoles, ","), r) {
			t.Fatalf("available roles %v miss %s", view.AvailableRoles, r)
		}
	}
	if code, _ := do(h.UpdateTenantMFAPolicy, http.MethodPatch, `{"required_roles":["bad role!"]}`, hadia.ID.String()); code != http.StatusBadRequest {
		t.Fatalf("invalid role code: %d", code)
	}
	if code, _ := do(h.UpdateTenantMFAPolicy, http.MethodPatch, `{"required_roles":[]}`, uuid.NewString()); code != http.StatusNotFound {
		t.Fatalf("unknown tenant: %d", code)
	}
	if code, view := do(h.UpdateTenantMFAPolicy, http.MethodPatch, `{"inherit":true}`, hadia.ID.String()); code != http.StatusOK || !view.Inherited {
		t.Fatalf("inherit: %d %+v", code, view)
	}

	if n := client.AuditLog.Query().Where(auditlog.ActionEQ("auth.mfa_policy.updated")).CountX(ctx); n != 3 {
		t.Fatalf("audited changes: %d, want 3", n)
	}
}

// The public tenant lookups keep the metadata services read and drop the MFA policy.
func TestPublicTenantResponseHidesTheMFAPolicy(t *testing.T) {
	got := publicTenantResponseFrom(&ent.Tenant{Metadata: map[string]any{
		"mfa_policy": map[string]any{}, "mfa_policy_default": map[string]any{}, "app_url": "https://example.com",
	}})
	if len(got.Metadata) != 1 || got.Metadata["app_url"] == nil {
		t.Fatalf("public metadata: %v", got.Metadata)
	}
}

// The generic tenant update never writes the MFA policy, and a tenant's own admin cannot set the
// keys that change what a token grants. A platform owner still can set those, but the MFA policy
// goes only through its own routes.
func TestUpdateTenantKeepsPlatformOnlyMetadata(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	h := &AdminHandler{ent: client, logger: zap.NewNop()}
	stored := map[string]any{"mfa_policy": map[string]any{"required_roles": []any{"hadia_admin"}, "all_accounts": false}}
	tn := client.Tenant.Create().SetName("Hadia").SetSlug("hadia-" + uuid.NewString()[:8]).SetMetadata(stored).SaveX(ctx)

	body := `{"metadata":{"mfa_policy":{"required_roles":[],"all_accounts":false},"is_platform_owner":true,"billing_mode":"service_charge","app_url":"https://example.com"}}`
	update := func(claims *token.Claims) map[string]any {
		rec := httptest.NewRecorder()
		h.UpdateTenant(rec, policyRequest(http.MethodPut, body, claims, tn.ID.String()))
		if rec.Code != http.StatusOK {
			t.Fatalf("update: %d %s", rec.Code, rec.Body.String())
		}
		return client.Tenant.GetX(ctx, tn.ID).Metadata
	}

	meta := update(&token.Claims{TenantID: tn.ID.String(), Roles: []string{"admin"}})
	if p, _ := auth.ParseMFAPolicy(meta["mfa_policy"]); strings.Join(p.RequiredRoles, ",") != "hadia_admin" {
		t.Fatalf("a tenant admin changed the MFA policy: %v", meta["mfa_policy"])
	}
	if meta["is_platform_owner"] != nil || meta["billing_mode"] != nil || meta["app_url"] != "https://example.com" {
		t.Fatalf("tenant admin update: %v", meta)
	}

	meta = update(&token.Claims{IsPlatformOwner: true})
	if p, _ := auth.ParseMFAPolicy(meta["mfa_policy"]); strings.Join(p.RequiredRoles, ",") != "hadia_admin" {
		t.Fatalf("the generic update wrote the MFA policy: %v", meta["mfa_policy"])
	}
	if meta["billing_mode"] != "service_charge" {
		t.Fatalf("a platform owner sets billing_mode: %v", meta)
	}
}
