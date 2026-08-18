package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
)

// Regression coverage for the 2026-08-18 platform-admin gating fix. The bug:
// requireAdmin/requirePlatformAdmin/CreateAPIKey accepted a bare "admin" or
// "superuser" role STRING from claims.Roles regardless of which tenant
// granted it. TenantMembership roles are tenant-scoped, not global, so this
// let the admin of ANY ordinary tenant (e.g. Urban Loft Cafe) manage every
// tenant, OAuth client, and rotate the platform's signing keys. The fix
// requires claims.IsPlatformOwner (computed elsewhere, scoped to an
// admin-tier role held specifically within the "codevertex" tenant) instead.
// These tests assert the FIXED behavior and must fail loudly if the
// bare-role-string shortcut is ever reintroduced.

func reqWithClaims(claims *token.Claims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if claims != nil {
		r = r.WithContext(authmiddleware.ContextWithClaims(r.Context(), claims))
	}
	return r
}

func TestIsPlatformAdminRole_Handlers(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"admin qualifies", []string{"admin"}, true},
		{"superuser qualifies", []string{"superuser"}, true},
		{"member alone does not qualify", []string{"member"}, false},
		{"custom COO role does not qualify", []string{"COO"}, false},
		{"empty roles does not qualify", []string{}, false},
		{"nil roles does not qualify", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPlatformAdminRole(c.roles); got != c.want {
				t.Errorf("isPlatformAdminRole(%v) = %v, want %v", c.roles, got, c.want)
			}
		})
	}
}

func TestIsPlatformOrS2SAdmin(t *testing.T) {
	cases := []struct {
		name   string
		claims *token.Claims
		want   bool
	}{
		{"platform owner passes", &token.Claims{IsPlatformOwner: true}, true},
		{"S2S admin scope passes", &token.Claims{Scope: []string{"admin"}}, true},
		{"S2S auth.admin scope passes", &token.Claims{Scope: []string{"auth.admin"}}, true},
		{
			"bare admin role from an ordinary tenant must NOT pass (the fixed vulnerability)",
			&token.Claims{Roles: []string{"admin"}, TenantID: "11111111-1111-1111-1111-111111111111"},
			false,
		},
		{
			"bare superuser role from an ordinary tenant must NOT pass",
			&token.Claims{Roles: []string{"superuser"}, TenantID: "22222222-2222-2222-2222-222222222222"},
			false,
		},
		{"unrelated scope does not pass", &token.Claims{Scope: []string{"profile"}}, false},
		{"empty claims does not pass", &token.Claims{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPlatformOrS2SAdmin(c.claims); got != c.want {
				t.Errorf("isPlatformOrS2SAdmin(%+v) = %v, want %v", c.claims, got, c.want)
			}
		})
	}
}

func TestRequirePlatformAdmin_AppHandler(t *testing.T) {
	cases := []struct {
		name   string
		claims *token.Claims
		want   bool
	}{
		{"platform owner passes", &token.Claims{IsPlatformOwner: true}, true},
		{
			"bare superuser role from an ordinary tenant must NOT pass (the fixed vulnerability)",
			&token.Claims{Roles: []string{"superuser"}, TenantID: "33333333-3333-3333-3333-333333333333"},
			false,
		},
		{"bare admin role does not pass (only superuser was ever accepted, and now neither is)", &token.Claims{Roles: []string{"admin"}}, false},
		{"empty claims does not pass", &token.Claims{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := requirePlatformAdmin(c.claims); got != c.want {
				t.Errorf("requirePlatformAdmin(%+v) = %v, want %v", c.claims, got, c.want)
			}
		})
	}
}

func TestAdminHandler_RequireAdmin(t *testing.T) {
	h := &AdminHandler{}
	cases := []struct {
		name   string
		claims *token.Claims
		want   bool
	}{
		{"platform owner passes", &token.Claims{IsPlatformOwner: true}, true},
		{"S2S admin scope passes", &token.Claims{Scope: []string{"admin"}}, true},
		{
			"bare admin role from an ordinary tenant must NOT pass platform-wide endpoints (the fixed vulnerability)",
			&token.Claims{Roles: []string{"admin"}, TenantID: "44444444-4444-4444-4444-444444444444"},
			false,
		},
		{
			"bare superuser role from an ordinary tenant must NOT pass",
			&token.Claims{Roles: []string{"superuser"}, TenantID: "55555555-5555-5555-5555-555555555555"},
			false,
		},
		{"no claims in context does not pass", nil, false},
		{"empty claims does not pass", &token.Claims{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.requireAdmin(reqWithClaims(c.claims)); got != c.want {
				t.Errorf("requireAdmin(%+v) = %v, want %v", c.claims, got, c.want)
			}
		})
	}
}

func TestRBACHandler_RequireAdmin(t *testing.T) {
	h := &RBACHandler{}
	cases := []struct {
		name   string
		claims *token.Claims
		want   bool
	}{
		{"platform owner passes", &token.Claims{IsPlatformOwner: true}, true},
		{"S2S admin scope passes", &token.Claims{Scope: []string{"auth.admin"}}, true},
		{
			"bare admin role from an ordinary tenant must NOT manage roles/permissions/audit-log platform-wide (the fixed vulnerability)",
			&token.Claims{Roles: []string{"admin"}, TenantID: "66666666-6666-6666-6666-666666666666"},
			false,
		},
		{"no claims in context does not pass", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.requireAdmin(reqWithClaims(c.claims)); got != c.want {
				t.Errorf("requireAdmin(%+v) = %v, want %v", c.claims, got, c.want)
			}
		})
	}
}

// Platform backup endpoints previously had NO authorization check at all —
// any authenticated user, any tenant, any role, could list/download every
// tenant's database backup. This asserts the newly-added rejection actually
// fires, using a zero-value handler struct (safe here: rejection returns
// before the handler touches its nil ent/store/settings dependencies).
//
// (A former sibling test here, TestDeveloperHandler_RejectsNonPlatformOwner,
// covered a redundant `/api/v1/developer/clients` OAuth-client-creation
// handler that has since been deleted and consolidated into AdminHandler's
// client CRUD — that authorization gate is covered by
// TestAdminHandler_RequireAdmin above, which exercises the same
// h.requireAdmin(...) call CreateClient/RotateClientSecret both use.)

func TestBackupHandler_RejectsNonPlatformOwner(t *testing.T) {
	h := &BackupHandler{}
	nonOwner := &token.Claims{Roles: []string{"superuser"}, TenantID: "88888888-8888-8888-8888-888888888888"}

	for _, tc := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"GetSettings", h.GetSettings},
		{"UpdateSettings", h.UpdateSettings},
		{"ListBackups", h.ListBackups},
		{"DownloadBackup", h.DownloadBackup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.fn(rec, reqWithClaims(nonOwner))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want %d (non-platform-owner must be rejected)", tc.name, rec.Code, http.StatusForbidden)
			}
		})
	}
}

func TestBackupDestinationHandler_RejectsNonPlatformOwner(t *testing.T) {
	h := &BackupDestinationHandler{}
	nonOwner := &token.Claims{Roles: []string{"admin"}, TenantID: "99999999-9999-9999-9999-999999999999"}

	for _, tc := range []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"Get", h.Get},
		{"Update", h.Update},
		{"Test", h.Test},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.fn(rec, reqWithClaims(nonOwner))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want %d (non-platform-owner must be rejected)", tc.name, rec.Code, http.StatusForbidden)
			}
		})
	}
}
