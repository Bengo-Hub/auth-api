package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/ent/auditlog"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
)

// Phase D (Hadia, 13 November 2026): removing a member through the real handler leaves one audit
// row on that tenant, naming the actor and the removed user by id and keeping the roles they held.
// The removed user's email or phone never goes into the row.
func TestRemoveTenantMemberWritesAuditEntry(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	shop := client.Tenant.Create().SetName("Shop").SetSlug("shop-" + sfx).SetStatus("active").SaveX(ctx)
	member := client.User.Create().SetEmail("gone-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
	client.TenantMembership.Create().SetUserID(member.ID).SetTenantID(shop.ID).
		SetRoles([]string{"cashier"}).SetStatus("active").SaveX(ctx)
	h := &AdminHandler{ent: client, logger: zap.NewNop(), auditor: audit.New(client, zap.NewNop())}

	actorID := uuid.New()
	claims := &token.Claims{IsPlatformOwner: true}
	claims.Subject = actorID.String()
	r := httptest.NewRequest(http.MethodDelete, "/", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("tenant_id", shop.ID.String())
	rc.URLParams.Add("user_id", member.ID.String())
	r = r.WithContext(context.WithValue(authmiddleware.ContextWithClaims(r.Context(), claims), chi.RouteCtxKey, rc))
	w := httptest.NewRecorder()
	h.RemoveTenantMember(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if n := client.TenantMembership.Query().Where(tenantmembership.UserID(member.ID), tenantmembership.TenantID(shop.ID)).CountX(ctx); n != 0 {
		t.Fatal("the membership must be gone")
	}

	rows := client.AuditLog.Query().Where(auditlog.Action("auth.tenant_member.removed"), auditlog.ResourceID(member.ID.String())).AllX(ctx)
	if len(rows) != 1 {
		t.Fatalf("want one audit row, got %d", len(rows))
	}
	row := rows[0]
	if row.TenantID != shop.ID {
		t.Fatalf("audit row must sit on the tenant: %s", row.TenantID)
	}
	if row.UserID != actorID {
		t.Fatalf("audit row must name the actor: %s", row.UserID)
	}
	if row.ResourceType != "tenant_membership" {
		t.Fatalf("resource type: %s", row.ResourceType)
	}
	if roles, ok := row.Context["removed_roles"].([]any); !ok || len(roles) != 1 || roles[0] != "cashier" {
		t.Fatalf("audit row must keep the removed roles: %v", row.Context)
	}
	for k, v := range row.Context {
		if s, ok := v.(string); ok && s == member.Email {
			t.Fatalf("the removed user's email must not be in the audit row (key %s)", k)
		}
	}

	// Removing someone who is not a member writes nothing.
	w = httptest.NewRecorder()
	h.RemoveTenantMember(w, r)
	if n := client.AuditLog.Query().Where(auditlog.Action("auth.tenant_member.removed"), auditlog.ResourceID(member.ID.String())).CountX(ctx); n != 1 {
		t.Fatalf("a second removal of a non-member must not add a row, got %d", n)
	}
}
