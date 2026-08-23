package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/enttest"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/bengobox/auth-api/internal/ent/resellerapplication"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"

	_ "github.com/lib/pq"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Pure decision-logic tests (no DB) ───────────────────────────────────────
//
// These mirror the codebase's existing pattern for unit-testing decision logic
// without a database (e.g. isAutoProvisionable in
// integration_request_service_test.go) — the equity flow this feature mirrors has
// no transition-order enforcement at all today (see legal_handler.go's
// UpdateApplication), so isValidResellerTransition is new, stricter logic that
// needs its own direct coverage.

func TestIsValidResellerTransition(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		// legal forward steps
		{"pending", "kyb_pending", true},
		{"kyb_pending", "kyb_approved", true},
		{"kyb_approved", "agreement_pending", true},
		{"agreement_pending", "approved", true},
		// rejection legal from any non-terminal stage
		{"pending", "rejected", true},
		{"kyb_pending", "rejected", true},
		{"kyb_approved", "rejected", true},
		{"agreement_pending", "rejected", true},
		// illegal: skipping a stage
		{"pending", "kyb_approved", false},
		{"pending", "agreement_pending", false},
		{"pending", "approved", false},
		{"kyb_pending", "agreement_pending", false},
		{"kyb_pending", "approved", false},
		{"kyb_approved", "approved", false},
		// illegal: backward
		{"kyb_pending", "pending", false},
		{"kyb_approved", "kyb_pending", false},
		{"agreement_pending", "kyb_approved", false},
		{"rejected", "pending", false},
		// illegal: out of a terminal state
		{"approved", "rejected", false},
		{"rejected", "approved", false},
		{"approved", "pending", false},
		{"approved", "kyb_pending", false},
		// illegal: no-op (from==to) — the idempotency guard is the caller's job, not this function's
		{"pending", "pending", false},
		{"approved", "approved", false},
		// illegal: empty/unknown values
		{"", "pending", false},
		{"pending", "", false},
		{"bogus", "pending", false},
		{"pending", "bogus", false},
	}
	for _, c := range cases {
		t.Run(c.from+"->"+c.to, func(t *testing.T) {
			if got := isValidResellerTransition(c.from, c.to); got != c.want {
				t.Errorf("isValidResellerTransition(%q, %q) = %v, want %v", c.from, c.to, got, c.want)
			}
		})
	}
}

func TestResellerApplicationEventPayload_FullyResolved(t *testing.T) {
	tenantID := uuid.New()
	acceptanceID := uuid.New()
	regNo := "C.123456"
	taxPin := "P051234567X"
	phone := "+254700000000"
	country := "KE"

	app := &ent.ResellerApplication{
		ID:                     uuid.New(),
		TenantID:               &tenantID,
		BusinessName:           "Acme Resellers Ltd",
		BusinessRegistrationNo: &regNo,
		TaxPin:                 &taxPin,
		ContactEmail:           "partners@acme.example",
		ContactPhone:           &phone,
		Country:                &country,
		RequestedTier:          resellerapplication.RequestedTierPremier,
		Status:                 resellerapplication.StatusApproved,
		KybReference:           "CASE-42",
		AgreementAcceptanceID:  &acceptanceID,
	}

	acceptedAt := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	payload := resellerApplicationEventPayload(app, "v1.0", &acceptedAt)

	want := map[string]any{
		"application_id":           app.ID.String(),
		"status":                   "approved",
		"business_name":            "Acme Resellers Ltd",
		"requested_tier":           "premier",
		"contact_email":            "partners@acme.example",
		"tenant_id":                tenantID.String(),
		"business_registration_no": regNo,
		"tax_pin":                  taxPin,
		"contact_phone":            phone,
		"country":                  country,
		"kyb_reference":            "CASE-42",
		"agreement_acceptance_id":  acceptanceID.String(),
		"agreement_doc_version":    "v1.0",
		"agreement_accepted_at":    acceptedAt.Format(time.RFC3339),
	}
	if len(payload) != len(want) {
		t.Fatalf("payload has %d keys, want %d\npayload=%+v\nwant=%+v", len(payload), len(want), payload, want)
	}
	for k, v := range want {
		if payload[k] != v {
			t.Errorf("payload[%q] = %v, want %v", k, payload[k], v)
		}
	}
}

// A brand-new-business application (no tenant yet, no agreement signed yet) must not
// leak placeholder/zero values for any of those not-yet-resolved fields into the event.
func TestResellerApplicationEventPayload_OmitsUnresolvedOptionalFields(t *testing.T) {
	app := &ent.ResellerApplication{
		ID:            uuid.New(),
		BusinessName:  "New Prospect Ltd",
		ContactEmail:  "hello@newprospect.example",
		RequestedTier: resellerapplication.RequestedTierRegistered,
		Status:        resellerapplication.StatusPending,
	}
	payload := resellerApplicationEventPayload(app, "", nil)

	for _, k := range []string{
		"tenant_id", "business_registration_no", "tax_pin", "contact_phone", "country",
		"kyb_reference", "agreement_acceptance_id", "agreement_doc_version", "agreement_accepted_at",
	} {
		if v, ok := payload[k]; ok {
			t.Errorf("payload unexpectedly contains %q = %v for a not-yet-resolved application", k, v)
		}
	}
	if payload["business_name"] != "New Prospect Ltd" {
		t.Errorf("payload business_name = %v, want %q", payload["business_name"], "New Prospect Ltd")
	}
}

// ─── Auth-gating tests (no DB) ────────────────────────────────────────────────
//
// Mirrors rbac_gate_test.go's zero-value-handler-struct pattern: the auth/admin
// check must reject the caller before the handler ever dereferences h.ent, so a
// ResellerHandler{} with a nil ent client is safe to exercise here.

func reqWithChiID(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestResellerHandler_RejectsUnauthenticated(t *testing.T) {
	h := &ResellerHandler{}
	cases := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"ListApplications", h.ListApplications},
		{"GetApplication", h.GetApplication},
		{"UpdateApplication", h.UpdateApplication},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := reqWithChiID(httptest.NewRequest(http.MethodGet, "/", nil), uuid.NewString())
			rec := httptest.NewRecorder()
			tc.fn(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s with no claims: status = %d, want %d", tc.name, rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestResellerHandler_RejectsBareTenantAdminRole(t *testing.T) {
	h := &ResellerHandler{}
	// A bare tenant-scoped "admin" TenantMembership role (claims.IsPlatformOwner is
	// false) must NOT qualify — only platform ownership or an admin-scoped S2S token
	// may approve/reject a reseller application or read the cross-tenant queue.
	nonPlatformAdmin := &token.Claims{Roles: []string{"admin"}, TenantID: uuid.NewString()}

	cases := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"ListApplications", h.ListApplications},
		{"GetApplication", h.GetApplication},
		{"UpdateApplication", h.UpdateApplication},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), nonPlatformAdmin))
			req = reqWithChiID(req, uuid.NewString())
			rec := httptest.NewRecorder()
			tc.fn(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with bare tenant 'admin' role: status = %d, want %d", tc.name, rec.Code, http.StatusForbidden)
			}
		})
	}
}

func TestResellerHandler_CreateApplication_RejectsMissingRequiredFields(t *testing.T) {
	h := &ResellerHandler{}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"business_name":""}`))
	rec := httptest.NewRecorder()
	h.CreateApplication(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("CreateApplication with empty business_name/contact_email: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// ─── DB-backed integration tests ──────────────────────────────────────────────
//
// These exercise the real transactional approval flow end-to-end (tenant
// create-vs-link branch, the outbox event committed alongside the status write)
// against a real local Postgres instance in an isolated, disposable schema — the
// same instance this project's Ent+Atlas migration workflow already requires
// (see internal/ent/migrate/main.go). Skips gracefully if unreachable so this
// file doesn't fail `go test ./...` in an environment with no local Postgres.

func resellerTestPostgresDSN() string {
	if v := os.Getenv("TEST_POSTGRES_URL"); v != "" {
		return v
	}
	return "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable"
}

// newResellerTestClient opens an Ent client against a fresh, isolated Postgres
// schema (auto-migrated from the CURRENT schema.go definitions via Ent's own
// schema.Create — independent of the versioned Atlas migration files), and drops
// the schema again on test cleanup. Skips the test if Postgres is unreachable.
func newResellerTestClient(t *testing.T) *ent.Client {
	t.Helper()
	base := resellerTestPostgresDSN()

	setupDB, err := sql.Open("postgres", base)
	if err != nil {
		t.Skipf("skipping DB-backed reseller handler test: cannot open postgres: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := setupDB.PingContext(ctx); err != nil {
		_ = setupDB.Close()
		t.Skipf("skipping DB-backed reseller handler test: postgres unreachable at %s: %v", base, err)
	}

	const schemaName = "ent_test_reseller_handler"
	if _, err := setupDB.Exec("CREATE SCHEMA IF NOT EXISTS " + schemaName); err != nil {
		_ = setupDB.Close()
		t.Fatalf("create test schema %s: %v", schemaName, err)
	}
	_ = setupDB.Close()

	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	dsn := base + sep + "search_path=" + schemaName

	client := enttest.Open(t, "postgres", dsn)
	t.Cleanup(func() {
		_ = client.Close()
		cleanupDB, err := sql.Open("postgres", base)
		if err != nil {
			return
		}
		_, _ = cleanupDB.Exec("DROP SCHEMA IF EXISTS " + schemaName + " CASCADE")
		_ = cleanupDB.Close()
	})
	return client
}

func newAdminPutRequest(id, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
	req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), &token.Claims{IsPlatformOwner: true}))
	return reqWithChiID(req, id)
}

func putStatus(t *testing.T, h *ResellerHandler, id, status string) *httptest.ResponseRecorder {
	t.Helper()
	req := newAdminPutRequest(id, fmt.Sprintf(`{"status":%q}`, status))
	rec := httptest.NewRecorder()
	h.UpdateApplication(rec, req)
	return rec
}

// TestResellerHandler_ApprovalCreatesNewTenant covers the "brand-new business, no
// tenant yet" branch: walking the full state machine to approved must create a new
// Tenant (is_reseller=true), backfill tenant_id onto the application, and emit the
// approved outbox event transactionally with the status write.
func TestResellerHandler_ApprovalCreatesNewTenant(t *testing.T) {
	client := newResellerTestClient(t)
	h := NewResellerHandler(client, zap.NewNop())
	ctx := context.Background()

	app, err := client.ResellerApplication.Create().
		SetBusinessName("Acme Resellers Ltd").
		SetContactEmail("partners@acme.example").
		SetRequestedTier(resellerapplication.RequestedTierCertified).
		SetStatus(resellerapplication.StatusPending).
		Save(ctx)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	for _, status := range []string{"kyb_pending", "kyb_approved", "agreement_pending", "approved"} {
		if rec := putStatus(t, h, app.ID.String(), status); rec.Code != http.StatusOK {
			t.Fatalf("transition to %s: status = %d, body = %s", status, rec.Code, rec.Body.String())
		}
	}

	got, err := client.ResellerApplication.Get(ctx, app.ID)
	if err != nil {
		t.Fatalf("reload application: %v", err)
	}
	if got.Status != resellerapplication.StatusApproved {
		t.Fatalf("status = %s, want approved", got.Status)
	}
	if got.TenantID == nil {
		t.Fatalf("tenant_id was not backfilled after approval created a new tenant")
	}

	newTenant, err := client.Tenant.Get(ctx, *got.TenantID)
	if err != nil {
		t.Fatalf("load newly created tenant: %v", err)
	}
	if !newTenant.IsReseller {
		t.Errorf("newly created tenant IsReseller = false, want true")
	}
	if newTenant.Name != "Acme Resellers Ltd" {
		t.Errorf("newly created tenant Name = %q, want %q", newTenant.Name, "Acme Resellers Ltd")
	}

	events, err := client.OutboxEvent.Query().
		Where(outboxevent.AggregateIDEQ(app.ID), outboxevent.EventTypeEQ("approved")).
		All(ctx)
	if err != nil {
		t.Fatalf("query outbox events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d 'approved' outbox events for this application, want exactly 1", len(events))
	}
	ev := events[0]
	if ev.AggregateType != "auth.reseller_application" {
		t.Errorf("aggregate_type = %q, want %q", ev.AggregateType, "auth.reseller_application")
	}
	if ev.TenantID != *got.TenantID {
		t.Errorf("outbox row tenant_id = %s, want the newly created tenant %s", ev.TenantID, *got.TenantID)
	}

	var envelope struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(ev.Payload, &envelope); err != nil {
		t.Fatalf("unmarshal outbox envelope: %v", err)
	}
	if envelope.Payload["tenant_id"] != got.TenantID.String() {
		t.Errorf("envelope payload tenant_id = %v, want %s", envelope.Payload["tenant_id"], got.TenantID.String())
	}
	if envelope.Payload["business_name"] != "Acme Resellers Ltd" {
		t.Errorf("envelope payload business_name = %v, want %q", envelope.Payload["business_name"], "Acme Resellers Ltd")
	}
	if envelope.Payload["requested_tier"] != "certified" {
		t.Errorf("envelope payload requested_tier = %v, want %q", envelope.Payload["requested_tier"], "certified")
	}
	if envelope.Payload["application_id"] != app.ID.String() {
		t.Errorf("envelope payload application_id = %v, want %s", envelope.Payload["application_id"], app.ID.String())
	}
}

// TestResellerHandler_ApprovalLinksExistingTenant covers the "existing tenant applying
// to also become a reseller" branch: approval must flip is_reseller on that SAME
// tenant and must NOT create a second one.
func TestResellerHandler_ApprovalLinksExistingTenant(t *testing.T) {
	client := newResellerTestClient(t)
	h := NewResellerHandler(client, zap.NewNop())
	ctx := context.Background()

	existingTenant, err := client.Tenant.Create().
		SetName("Urban Loft Cafe").
		SetSlug("urban-loft-cafe-" + uuid.New().String()[:8]).
		SetStatus("active").
		Save(ctx)
	if err != nil {
		t.Fatalf("seed existing tenant: %v", err)
	}

	app, err := client.ResellerApplication.Create().
		SetTenantID(existingTenant.ID).
		SetBusinessName("Urban Loft Cafe").
		SetContactEmail("ops@urbanloft.example").
		SetStatus(resellerapplication.StatusPending).
		Save(ctx)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	for _, status := range []string{"kyb_pending", "kyb_approved", "agreement_pending", "approved"} {
		if rec := putStatus(t, h, app.ID.String(), status); rec.Code != http.StatusOK {
			t.Fatalf("transition to %s: status = %d, body = %s", status, rec.Code, rec.Body.String())
		}
	}

	reloadedTenant, err := client.Tenant.Get(ctx, existingTenant.ID)
	if err != nil {
		t.Fatalf("reload existing tenant: %v", err)
	}
	if !reloadedTenant.IsReseller {
		t.Errorf("existing tenant IsReseller = false after approval, want true")
	}

	count, err := client.Tenant.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count tenants: %v", err)
	}
	if count != 1 {
		t.Errorf("tenant count = %d, want 1 (approval must link the existing tenant, not create a second one)", count)
	}

	reloadedApp, err := client.ResellerApplication.Get(ctx, app.ID)
	if err != nil {
		t.Fatalf("reload application: %v", err)
	}
	if reloadedApp.TenantID == nil || *reloadedApp.TenantID != existingTenant.ID {
		t.Errorf("application tenant_id = %v, want unchanged %s", reloadedApp.TenantID, existingTenant.ID)
	}
}

// TestResellerHandler_InvalidTransitionsRejected exercises the handler-level state
// machine guard end-to-end: skipped stages, backward moves, and repeated same-status
// PUTs must all be rejected without mutating the application or creating a tenant, and
// rejection must remain reachable from a non-terminal, pre-approval stage.
func TestResellerHandler_InvalidTransitionsRejected(t *testing.T) {
	client := newResellerTestClient(t)
	h := NewResellerHandler(client, zap.NewNop())
	ctx := context.Background()

	app, err := client.ResellerApplication.Create().
		SetBusinessName("Skippy Ventures").
		SetContactEmail("hello@skippy.example").
		SetStatus(resellerapplication.StatusPending).
		Save(ctx)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	// pending -> approved skips kyb_pending/kyb_approved/agreement_pending.
	if rec := putStatus(t, h, app.ID.String(), "approved"); rec.Code != http.StatusBadRequest {
		t.Fatalf("pending->approved: status = %d, want %d, body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if reloaded, _ := client.ResellerApplication.Get(ctx, app.ID); reloaded.Status != resellerapplication.StatusPending {
		t.Fatalf("status changed to %s after a rejected transition, want unchanged pending", reloaded.Status)
	}
	if n, _ := client.Tenant.Query().Count(ctx); n != 0 {
		t.Errorf("a tenant was created despite the invalid transition being rejected (count=%d)", n)
	}

	// Same-status PUT is a no-op, rejected as a conflict, not a transition.
	if rec := putStatus(t, h, app.ID.String(), "pending"); rec.Code != http.StatusConflict {
		t.Fatalf("same-status PUT: status = %d, want %d", rec.Code, http.StatusConflict)
	}

	// Advance one legal step, then attempt to go backward.
	if rec := putStatus(t, h, app.ID.String(), "kyb_pending"); rec.Code != http.StatusOK {
		t.Fatalf("pending->kyb_pending: status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec := putStatus(t, h, app.ID.String(), "pending"); rec.Code != http.StatusBadRequest {
		t.Fatalf("kyb_pending->pending (backward): status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Rejection remains legal from this earlier, non-terminal stage.
	if rec := putStatus(t, h, app.ID.String(), "rejected"); rec.Code != http.StatusOK {
		t.Fatalf("kyb_pending->rejected: status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// No further transition may leave a terminal state.
	if rec := putStatus(t, h, app.ID.String(), "kyb_pending"); rec.Code != http.StatusBadRequest {
		t.Fatalf("rejected->kyb_pending: status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
