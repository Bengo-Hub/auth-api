package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/enttest"
	"github.com/bengobox/auth-api/internal/ent/legalacceptance"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Pure tests (no DB) ───────────────────────────────────────────────────────

func TestNormalizeDocType(t *testing.T) {
	cases := map[string]string{
		"marketflow-autopublish-terms":  DocTypeMarketFlowAutoPublishTerms,
		" MARKETFLOW_AUTOPUBLISH_TERMS": DocTypeMarketFlowAutoPublishTerms,
		"dpa":                           "DPA",
		"reseller-agreement":            "RESELLER_AGREEMENT",
	}
	for in, want := range cases {
		if got := normalizeDocType(in); got != want {
			t.Errorf("normalizeDocType(%q) = %q, want %q", in, got, want)
		}
		if !isValidDocType(normalizeDocType(in)) {
			t.Errorf("%q should be a valid doc type", in)
		}
	}
	if isValidDocType("TERMS") {
		t.Error("unknown doc type accepted")
	}
	if !isEffectiveDated(DocTypeMarketFlowAutoPublishTerms) || isEffectiveDated("EPA") {
		t.Error("only the MarketFlow auto-publish terms are effective-dated")
	}
}

func TestParseEffectiveDate(t *testing.T) {
	d, err := parseEffectiveDate("2026-12-01")
	if err != nil || !d.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("date only: %v %v", d, err)
	}
	d, err = parseEffectiveDate("2026-12-01T00:00:00+03:00")
	if err != nil || !d.Equal(time.Date(2026, 11, 30, 21, 0, 0, 0, time.UTC)) {
		t.Fatalf("rfc3339: %v %v", d, err)
	}
	if _, err := parseEffectiveDate("1 Dec 2026"); err == nil {
		t.Fatal("free text accepted")
	}
}

func TestMinNotice_Config(t *testing.T) {
	day := 24 * time.Hour
	h := NewLegalHandler(nil, nil, zap.NewNop())
	if got := h.minNotice(DocTypeMarketFlowAutoPublishTerms); got != 14*day {
		t.Fatalf("default = %v, want 14 days", got)
	}
	if got := h.minNotice("EPA"); got != 0 {
		t.Fatalf("EPA = %v, want 0 (not effective-dated)", got)
	}
	h.WithMinNotice(7, "")
	if got := h.minNotice(DocTypeMarketFlowAutoPublishTerms); got != 7*day {
		t.Fatalf("LEGAL_MIN_NOTICE_DAYS=7 gives %v", got)
	}
	h.WithMinNotice(7, " marketflow-autopublish-terms=30, BOGUS=1, EPA=x")
	if got := h.minNotice(DocTypeMarketFlowAutoPublishTerms); got != 30*day {
		t.Fatalf("per-type override gives %v, want 30 days", got)
	}
	h.WithMinNotice(0, "")
	if got := h.minNotice(DocTypeMarketFlowAutoPublishTerms); got != 0 {
		t.Fatalf("0 days gives %v, want no minimum", got)
	}
	h.WithMinNotice(-1, "")
	if got := h.minNotice(DocTypeMarketFlowAutoPublishTerms); got != 0 {
		t.Fatalf("negative keeps the previous value; got %v", got)
	}
}

// The configured notice is what the admin endpoint enforces.
func TestUpsertDocument_ConfiguredNoticeRefusedBeforeDB(t *testing.T) {
	h := NewLegalHandler(nil, nil, zap.NewNop()).WithMinNotice(14, "MARKETFLOW_AUTOPUBLISH_TERMS=30")
	in20 := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.DateOnly)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","version":"1","html_content":"<p>x</p>","effective_date":"`+in20+`"}`))
	req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), &token.Claims{IsPlatformOwner: true}))
	rec := httptest.NewRecorder()
	h.UpsertDocument(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "notice_too_short") {
		t.Fatalf("20 days against a 30 day minimum: %d %s", rec.Code, rec.Body.String())
	}
}

func TestS2SAcceptForTenant_RefusesPlatformAgreements(t *testing.T) {
	h := &LegalHandler{logger: zap.NewNop()}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"doc_type":"EPA","doc_version":"v1"}`))
	req = withChiParams(req, map[string]string{"tenant_id": uuid.NewString()})
	rec := httptest.NewRecorder()
	h.S2SAcceptForTenant(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// ─── DB-backed tests ──────────────────────────────────────────────────────────
//
// Same harness as reseller_handler_test.go: a disposable Postgres schema migrated from the
// current schema.go, skipped when no local Postgres answers.

func newLegalTestClient(t *testing.T) *ent.Client {
	t.Helper()
	base := resellerTestPostgresDSN()
	setupDB, err := sql.Open("postgres", base)
	if err != nil {
		t.Skipf("skipping DB-backed legal test: cannot open postgres: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := setupDB.PingContext(ctx); err != nil {
		_ = setupDB.Close()
		t.Skipf("skipping DB-backed legal test: postgres unreachable at %s: %v", base, err)
	}
	const schemaName = "ent_test_legal_versions"
	if _, err := setupDB.Exec("DROP SCHEMA IF EXISTS " + schemaName + " CASCADE; CREATE SCHEMA " + schemaName); err != nil {
		_ = setupDB.Close()
		t.Fatalf("create test schema %s: %v", schemaName, err)
	}
	_ = setupDB.Close()
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	client := enttest.Open(t, "postgres", base+sep+"search_path="+schemaName)
	t.Cleanup(func() {
		_ = client.Close()
		if db, err := sql.Open("postgres", base); err == nil {
			_, _ = db.Exec("DROP SCHEMA IF EXISTS " + schemaName + " CASCADE")
			_ = db.Close()
		}
	})
	return client
}

func withChiParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func seedTermsVersion(t *testing.T, c *ent.Client, version string, effective time.Time) {
	t.Helper()
	if _, err := c.LegalDocument.Create().
		SetDocType(legaldocument.DocType(DocTypeMarketFlowAutoPublishTerms)).
		SetVersion(version).
		SetHTMLContent("<p>terms " + version + "</p>").
		SetEffectiveDate(effective).
		Save(context.Background()); err != nil {
		t.Fatalf("seed version %s: %v", version, err)
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestLegalVersions_CurrentFollowsEffectiveDate(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	now := time.Now()

	get := func() *httptest.ResponseRecorder {
		req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"type": "marketflow-autopublish-terms"})
		rec := httptest.NewRecorder()
		h.GetCurrentDocument(rec, req)
		return rec
	}

	if rec := get(); rec.Code != http.StatusNotFound {
		t.Fatalf("nothing published: status = %d, want 404", rec.Code)
	}

	seedTermsVersion(t, client, "v1", now.Add(-48*time.Hour))
	seedTermsVersion(t, client, "v2", now.Add(14*24*time.Hour))

	rec := get()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["version"] != "v1" {
		t.Errorf("version in force = %v, want v1", body["version"])
	}
	up, _ := body["upcoming"].(map[string]any)
	if up == nil || up["version"] != "v2" || up["in_force"] != false {
		t.Errorf("upcoming = %v, want v2 not in force", body["upcoming"])
	}

	// One version: GET by version returns it with its body, including the upcoming one.
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"type": "marketflow-autopublish-terms", "version": "v2"})
	rec = httptest.NewRecorder()
	h.GetDocumentVersion(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "terms v2") {
		t.Fatalf("version v2: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLegalVersions_AdminUpsertRules(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	admin := &token.Claims{IsPlatformOwner: true}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), admin))
		rec := httptest.NewRecorder()
		h.UpsertDocument(rec, req)
		return rec
	}

	soon := time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.DateOnly)
	if rec := post(`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","version":"v1","html_content":"<p>x</p>","effective_date":"` + soon + `"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("short notice: status = %d, want 400", rec.Code)
	}
	if rec := post(`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","version":"v1","html_content":"<p>x</p>","effective_date":"` + soon + `","skip_notice":true}`); rec.Code != http.StatusOK {
		t.Fatalf("skip_notice: status = %d: %s", rec.Code, rec.Body.String())
	}
	later := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.DateOnly)
	if rec := post(`{"doc_type":"marketflow-autopublish-terms","version":"v2","html_content":"<p>y</p>","effective_date":"` + later + `","set_current":true}`); rec.Code != http.StatusOK {
		t.Fatalf("v2: status = %d: %s", rec.Code, rec.Body.String())
	}
	// set_current is ignored for an effective-dated type.
	if n, _ := client.LegalDocument.Query().Where(legaldocument.IsCurrentEQ(true)).Count(context.Background()); n != 0 {
		t.Errorf("is_current set on %d rows, want 0", n)
	}

	// A version in force is immutable.
	seedTermsVersion(t, client, "v0", time.Now().Add(-time.Hour))
	if rec := post(`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","version":"v0","html_content":"<p>z</p>","effective_date":"` + later + `"}`); rec.Code != http.StatusConflict {
		t.Fatalf("edit in force: status = %d, want 409", rec.Code)
	}
}

func TestLegalVersions_AcceptAndList(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	ctx := context.Background()
	tenantID, userID := uuid.New(), uuid.New()

	seedTermsVersion(t, client, "v0", time.Now().Add(-90*24*time.Hour))
	seedTermsVersion(t, client, "v1", time.Now().Add(-time.Hour))
	seedTermsVersion(t, client, "v2", time.Now().Add(14*24*time.Hour))

	s2sAccept := func(version string) *httptest.ResponseRecorder {
		body := `{"doc_type":"marketflow-autopublish-terms","doc_version":"` + version + `","user_id":"` + userID.String() + `","ip_address":"203.0.113.9","user_agent":"test"}`
		req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), map[string]string{"tenant_id": tenantID.String()})
		rec := httptest.NewRecorder()
		h.S2SAcceptForTenant(rec, req)
		return rec
	}

	if rec := s2sAccept("v0"); rec.Code != http.StatusConflict {
		t.Fatalf("superseded version: status = %d, want 409", rec.Code)
	}
	if rec := s2sAccept("v9"); rec.Code != http.StatusConflict {
		t.Fatalf("unknown version: status = %d, want 409", rec.Code)
	}
	if rec := s2sAccept("v2"); rec.Code != http.StatusCreated {
		t.Fatalf("upcoming version: status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := s2sAccept("v2"); rec.Code != http.StatusOK {
		t.Fatalf("repeat accept: status = %d, want 200", rec.Code)
	}
	n, _ := client.LegalAcceptance.Query().Where(legalacceptance.EntityIDEQ(tenantID)).Count(ctx)
	if n != 1 {
		t.Fatalf("acceptances = %d, want 1 (idempotent)", n)
	}

	// The user's own token: accepts the version in force and records the user.
	body := `{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","doc_version":"v1"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	claims := &token.Claims{TenantID: tenantID.String()}
	claims.Subject = userID.String()
	req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.AcceptDocument(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("user accept: status = %d: %s", rec.Code, rec.Body.String())
	}
	if decodeBody(t, rec)["accepted_by_user_id"] != userID.String() {
		t.Errorf("accepted_by_user_id missing: %s", rec.Body.String())
	}

	// Listing, S2S and the user's own, filtered by type.
	req = withChiParams(httptest.NewRequest(http.MethodGet, "/?doc_type=marketflow-autopublish-terms", nil), map[string]string{"tenant_id": tenantID.String()})
	rec = httptest.NewRecorder()
	h.S2SListTenantAcceptances(rec, req)
	list, _ := decodeBody(t, rec)["acceptances"].([]any)
	if rec.Code != http.StatusOK || len(list) != 2 {
		t.Fatalf("s2s list: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/?doc_type=EPA", nil)
	req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), claims))
	rec = httptest.NewRecorder()
	h.ListMyAcceptances(rec, req)
	list, _ = decodeBody(t, rec)["acceptances"].([]any)
	if rec.Code != http.StatusOK || len(list) != 0 {
		t.Fatalf("own list filtered to EPA: %d %s", rec.Code, rec.Body.String())
	}
}
