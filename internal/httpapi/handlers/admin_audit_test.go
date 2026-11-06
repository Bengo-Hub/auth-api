package handlers

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/ent/auditlog"
	"github.com/bengobox/auth-api/internal/ent/enttest"
)

// A removed membership leaves an audit row on the tenant it was removed from, with the roles it held.
func TestAdminWriteAuditRecordsMemberRemoval(t *testing.T) {
	base := resellerTestPostgresDSN()
	setup, err := sql.Open("postgres", base)
	if err != nil || setup.Ping() != nil {
		t.Skip("local postgres unavailable")
	}
	schema := "ent_test_admin_audit_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := setup.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = setup.Exec("DROP SCHEMA " + schema + " CASCADE"); _ = setup.Close() })
	dsn := base + "&search_path=" + schema
	if !strings.Contains(base, "?") {
		dsn = base + "?search_path=" + schema
	}
	client := enttest.Open(t, "postgres", dsn)
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	h := &AdminHandler{ent: client, logger: zap.NewNop(), auditor: audit.New(client, zap.NewNop())}

	tenantID, memberID := uuid.New(), uuid.New()
	r := httptest.NewRequest("DELETE", "/api/v1/admin/tenants/x/members/y", nil)
	h.writeAudit(r, tenantID, "auth.tenant_member.removed", "tenant_membership", memberID.String(),
		map[string]any{"removed_roles": []string{"superuser"}})

	row, err := client.AuditLog.Query().Where(auditlog.Action("auth.tenant_member.removed")).Only(ctx)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if row.TenantID != tenantID || row.ResourceID != memberID.String() {
		t.Fatalf("audit row must name the tenant and the removed member: %+v", row)
	}
	if roles, ok := row.Context["removed_roles"].([]any); !ok || len(roles) != 1 || roles[0] != "superuser" {
		t.Fatalf("audit row must keep the removed roles: %v", row.Context)
	}
}
