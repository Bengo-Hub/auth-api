package handlers

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/enttest"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
)

// A purged tenant leaves nothing in auth: an account only it held goes with its sessions, an
// account in another tenant keeps that membership, outlets and the tenant row go, the other
// tenant is untouched, tenant.purge is queued for the services, and the platform tenant is refused.
func TestPurgeTenant(t *testing.T) {
	base := resellerTestPostgresDSN()
	setup, err := sql.Open("postgres", base)
	if err != nil || setup.Ping() != nil {
		t.Skip("local postgres unavailable")
	}
	schema := "ent_test_tenant_purge_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
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
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	h := &AdminHandler{ent: client, db: db, logger: zap.NewNop()}

	newTenant := func(slug string) *ent.Tenant {
		return client.Tenant.Create().SetName(slug).SetSlug(slug).SaveX(ctx)
	}
	gone, other := newTenant("declined-shop"), newTenant("other-shop")
	only := client.User.Create().SetEmail("only@declined.test").SetPrimaryTenantID(gone.ID.String()).SaveX(ctx)
	both := client.User.Create().SetEmail("both@declined.test").SetPrimaryTenantID(other.ID.String()).SaveX(ctx)
	client.TenantMembership.Create().SetTenantID(gone.ID).SetUserID(only.ID).SetRoles([]string{"admin"}).ExecX(ctx)
	client.TenantMembership.Create().SetTenantID(gone.ID).SetUserID(both.ID).SetRoles([]string{"cashier"}).ExecX(ctx)
	client.TenantMembership.Create().SetTenantID(other.ID).SetUserID(both.ID).SetRoles([]string{"admin"}).ExecX(ctx)
	client.Session.Create().SetUserID(only.ID).SetTenantID(gone.ID).SetRefreshTokenHash("h").SetSessionType("user").
		SetStatus("active").SetExpiresAt(time.Now().Add(time.Hour)).ExecX(ctx)
	client.Outlet.Create().SetTenantID(gone.ID).SetName("Main").SetCode("MAIN").ExecX(ctx)

	if err := h.purgeTenant(ctx, gone, sharedevents.PurgeReasonRegistrationRejected); err != nil {
		t.Fatal(err)
	}
	if client.Tenant.Query().CountX(ctx) != 1 || client.Outlet.Query().CountX(ctx) != 0 {
		t.Fatal("the tenant and its outlets must be gone, the other tenant kept")
	}
	if n, _ := client.User.Query().Count(ctx); n != 1 || client.Session.Query().CountX(ctx) != 0 {
		t.Fatalf("the account only the tenant held must go with its sessions (users left %d)", n)
	}
	if !client.TenantMembership.Query().Where(tenantmembership.UserID(both.ID), tenantmembership.TenantID(other.ID)).ExistX(ctx) {
		t.Fatal("the account in another tenant must keep that membership")
	}
	if !client.OutboxEvent.Query().Where(outboxevent.AggregateType("tenant"), outboxevent.EventType("purge")).ExistX(ctx) {
		t.Fatal("tenant.purge must be queued for the services")
	}

	platform := newTenant(platformTenantSlug)
	if err := h.purgeTenant(ctx, platform, sharedevents.PurgeReasonTenantDeleted); err == nil {
		t.Fatal("the platform tenant must be refused")
	}
}
