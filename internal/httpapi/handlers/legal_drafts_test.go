package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ─── Pure tests (no DB) ───────────────────────────────────────────────────────

func TestProposedEffectiveDate(t *testing.T) {
	now := time.Date(2026, 11, 14, 22, 30, 0, 0, time.UTC)
	got := proposedEffectiveDate(now, 14*24*time.Hour)
	if want := time.Date(2026, 11, 29, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("proposed = %v, want %v (first midnight after the notice)", got, want)
	}
	midnight := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	if got := proposedEffectiveDate(midnight, 0); !got.Equal(midnight) {
		t.Fatalf("exact midnight with no notice = %v, want %v", got, midnight)
	}
}

func draftRequest(method, body string, claims *token.Claims, params map[string]string) *http.Request {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	if claims != nil {
		req = req.WithContext(authmiddleware.ContextWithClaims(req.Context(), claims))
	}
	return withChiParams(req, params)
}

// Every draft endpoint is platform-admin only, and refuses before touching the database.
func TestDraftEndpoints_AdminOnly(t *testing.T) {
	h := NewLegalHandler(nil, nil, zap.NewNop())
	params := map[string]string{"type": "marketflow-autopublish-terms", "version": "1"}
	tenantAdmin := &token.Claims{TenantID: uuid.NewString(), Roles: []string{"admin"}}
	cases := map[string]func(http.ResponseWriter, *http.Request){
		"list":     h.AdminListVersions,
		"get":      h.AdminGetVersion,
		"save":     h.SaveDraft,
		"publish":  h.PublishDraft,
		"discard":  h.DiscardDraft,
		"overview": h.AdminOverview,
	}
	for name, fn := range cases {
		rec := httptest.NewRecorder()
		fn(rec, draftRequest(http.MethodPost, `{}`, nil, params))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d, want 401", name, rec.Code)
		}
		rec = httptest.NewRecorder()
		fn(rec, draftRequest(http.MethodPost, `{}`, tenantAdmin, params))
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s as a tenant admin: %d, want 403", name, rec.Code)
		}
	}
}

func TestDraftEndpoints_RefusedBeforeDB(t *testing.T) {
	h := NewLegalHandler(nil, nil, zap.NewNop()).WithMinNotice(14, "")
	admin := &token.Claims{IsPlatformOwner: true}

	// An unknown type.
	rec := httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>x</p>"}`, admin, map[string]string{"type": "nda", "version": "1"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_doc_type") {
		t.Fatalf("unknown type draft: %d %s", rec.Code, rec.Body.String())
	}

	// A title or summary that is too long.
	rec = httptest.NewRecorder()
	long := strings.Repeat("x", maxLegalTitle+1)
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>x</p>","title":"`+long+`"}`, admin, map[string]string{"type": "terms-of-service", "version": "2"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_metadata") {
		t.Fatalf("long title: %d %s", rec.Code, rec.Body.String())
	}

	// A version that cannot be a URL segment.
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>x</p>"}`, admin, map[string]string{"type": "marketflow-autopublish-terms", "version": "v 1/2"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_version") {
		t.Fatalf("bad version: %d %s", rec.Code, rec.Body.String())
	}

	// An empty body.
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"  "}`, admin, map[string]string{"type": "marketflow-autopublish-terms", "version": "1"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_content") {
		t.Fatalf("empty body: %d %s", rec.Code, rec.Body.String())
	}

	params := map[string]string{"type": "marketflow-autopublish-terms", "version": "1"}
	// Publishing needs an effective date.
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{}`, admin, params))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_date") {
		t.Fatalf("publish without a date: %d %s", rec.Code, rec.Body.String())
	}
	// And gives the configured notice.
	in5 := time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.DateOnly)
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{"effective_date":"`+in5+`"}`, admin, params))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "notice_too_short") {
		t.Fatalf("publish on 5 days notice: %d %s", rec.Code, rec.Body.String())
	}
}

// ─── DB-backed tests ──────────────────────────────────────────────────────────

func TestLegalDrafts_HiddenUntilPublished(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	ctx := context.Background()
	admin := &token.Claims{IsPlatformOwner: true}
	typeParams := map[string]string{"type": "marketflow-autopublish-terms"}
	v1 := map[string]string{"type": "marketflow-autopublish-terms", "version": "1"}

	// Save the draft with no date: it gets a proposed one and is created (201).
	rec := httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>draft one</p>"}`, admin, v1))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create draft: %d %s", rec.Code, rec.Body.String())
	}
	if b := decodeBody(t, rec); b["status"] != "draft" || b["in_force"] != false {
		t.Fatalf("draft response: %v", b)
	}
	// Saving again edits it (200), here with a past date to prove a draft is never in force.
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>draft two</p>","effective_date":"2020-01-01"}`, admin, v1))
	if rec.Code != http.StatusOK {
		t.Fatalf("edit draft: %d %s", rec.Code, rec.Body.String())
	}

	// Public reads do not see it.
	rec = httptest.NewRecorder()
	h.GetCurrentDocument(rec, withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), typeParams))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("public current with only a draft: %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.GetDocumentVersion(rec, withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), v1))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("public version read of a draft: %d, want 404", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ListDocumentVersions(rec, withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), typeParams))
	if list, _ := decodeBody(t, rec)["versions"].([]any); len(list) != 0 {
		t.Fatalf("public list shows the draft: %s", rec.Body.String())
	}

	// It cannot be accepted.
	rec = httptest.NewRecorder()
	h.S2SAcceptForTenant(rec, withChiParams(httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","doc_version":"1"}`)),
		map[string]string{"tenant_id": uuid.NewString()}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("accepting a draft: %d, want 409", rec.Code)
	}

	// The direct publish endpoint does not touch a draft.
	later := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.DateOnly)
	rec = httptest.NewRecorder()
	h.UpsertDocument(rec, draftRequest(http.MethodPost,
		`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","version":"1","html_content":"<p>x</p>","effective_date":"`+later+`"}`, admin, nil))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "version_is_draft") {
		t.Fatalf("upsert over a draft: %d %s", rec.Code, rec.Body.String())
	}

	// The admin sees it, with its body and the notice rule.
	rec = httptest.NewRecorder()
	h.AdminGetVersion(rec, draftRequest(http.MethodGet, "", admin, v1))
	b := decodeBody(t, rec)
	if rec.Code != http.StatusOK || b["html_content"] != "<p>draft two</p>" || b["notice"] == nil {
		t.Fatalf("admin preview: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.AdminListVersions(rec, withChiParams(
		authedGet("/?status=draft", admin), typeParams))
	if list, _ := decodeBody(t, rec)["versions"].([]any); rec.Code != http.StatusOK || len(list) != 1 {
		t.Fatalf("admin draft list: %d %s", rec.Code, rec.Body.String())
	}

	// Publish on short notice is refused, then accepted with the full notice.
	rec = httptest.NewRecorder()
	soon := time.Now().Add(2 * 24 * time.Hour).UTC().Format(time.DateOnly)
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{"effective_date":"`+soon+`"}`, admin, v1))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short notice publish: %d, want 400", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{"effective_date":"`+later+`"}`, admin, v1))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	doc, err := client.LegalDocument.Query().Where(legaldocument.VersionEQ("1")).Only(ctx)
	if err != nil || doc.Status != legaldocument.StatusPublished || doc.EffectiveDate.UTC().Format(time.DateOnly) != later {
		t.Fatalf("after publish: %+v %v", doc, err)
	}

	// Now public and upcoming, acceptable, and no longer a draft.
	rec = httptest.NewRecorder()
	h.GetCurrentDocument(rec, withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), typeParams))
	up, _ := decodeBody(t, rec)["upcoming"].(map[string]any)
	if rec.Code != http.StatusOK || up == nil || up["version"] != "1" {
		t.Fatalf("public after publish: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{"effective_date":"`+later+`"}`, admin, v1))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second publish: %d, want 409", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>again</p>"}`, admin, v1))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "version_published") {
		t.Fatalf("draft over a published version: %d %s", rec.Code, rec.Body.String())
	}
}

func TestLegalDrafts_SkipNoticePublish(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	admin := &token.Claims{IsPlatformOwner: true}
	v := map[string]string{"type": "MARKETFLOW_AUTOPUBLISH_TERMS", "version": "1"}

	rec := httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>urgent</p>"}`, admin, v))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create draft: %d %s", rec.Code, rec.Body.String())
	}
	today := time.Now().UTC().Format(time.DateOnly)
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{"effective_date":"`+today+`","skip_notice":true}`, admin, v))
	if rec.Code != http.StatusOK {
		t.Fatalf("skip_notice publish: %d %s", rec.Code, rec.Body.String())
	}
	// In force from today, so the published rules make it immutable.
	rec = httptest.NewRecorder()
	later := time.Now().Add(20 * 24 * time.Hour).UTC().Format(time.DateOnly)
	h.UpsertDocument(rec, draftRequest(http.MethodPost,
		`{"doc_type":"MARKETFLOW_AUTOPUBLISH_TERMS","version":"1","html_content":"<p>edit</p>","effective_date":"`+later+`"}`, admin, nil))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "document_in_force") {
		t.Fatalf("edit after publish in force: %d %s", rec.Code, rec.Body.String())
	}
}

// Notices are never accepted, and a service cannot record a user's own Terms of Service consent.
func TestPolicyAcceptance_RefusedBeforeDB(t *testing.T) {
	h := NewLegalHandler(nil, nil, zap.NewNop())
	user := &token.Claims{TenantID: uuid.NewString()}
	user.Subject = uuid.NewString()
	rec := httptest.NewRecorder()
	h.AcceptDocument(rec, draftRequest(http.MethodPost, `{"doc_type":"COOKIE_POLICY","doc_version":"1"}`, user, nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not_acceptable") {
		t.Fatalf("accepting a notice: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.S2SAcceptForTenant(rec, withChiParams(httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"doc_type":"TERMS_OF_SERVICE","doc_version":"1"}`)),
		map[string]string{"tenant_id": uuid.NewString()}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("service accepting terms of service: %d, want 403", rec.Code)
	}
	if docTypeKind(DocTypeTermsOfService) != "user_consent" || docTypeKind(DocTypeRefundPolicy) != "notice" ||
		docTypeKind(DocTypeMarketFlowAutoPublishTerms) != "product_terms" || docTypeKind("MSA") != "agreement" {
		t.Fatal("docTypeKind mapping changed")
	}
}

func seedPolicyVersion(t *testing.T, c *ent.Client, docType, version string, effective time.Time, material bool) {
	t.Helper()
	if _, err := c.LegalDocument.Create().
		SetDocType(legaldocument.DocType(docType)).
		SetVersion(version).
		SetHTMLContent("<p>" + docType + " " + version + "</p>").
		SetEffectiveDate(effective).
		SetMetadata(map[string]any{"material": material, "title": docType + " " + version}).
		Save(context.Background()); err != nil {
		t.Fatalf("seed %s %s: %v", docType, version, err)
	}
}

// A material Terms of Service change asks users who signed up before it to accept again; a user
// who signed up later, or who accepted it, owes nothing.
func TestLegalPolicies_UserConsentState(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	ctx := context.Background()
	now := time.Now()
	day := 24 * time.Hour
	seedPolicyVersion(t, client, DocTypeTermsOfService, "1", now.Add(-60*day), false)
	seedPolicyVersion(t, client, DocTypeTermsOfService, "2", now.Add(-10*day), true)
	seedPolicyVersion(t, client, DocTypeTermsOfService, "3", now.Add(-2*day), false)

	userID := uuid.New()
	signedUp := now.Add(-30 * day)
	st, err := h.userConsentState(ctx, userID, &signedUp, DocTypeTermsOfService, now)
	if err != nil || st.required == nil || st.required.Version != "3" {
		t.Fatalf("older user must accept the version in force (3) after material 2: %+v %v", st.required, err)
	}
	recent := now.Add(-5 * day)
	if st, _ := h.userConsentState(ctx, userID, &recent, DocTypeTermsOfService, now); st.required != nil {
		t.Fatalf("user who signed up after the material change owes nothing: %v", st.required.Version)
	}

	// The user accepts version 3 with their own token.
	claims := &token.Claims{TenantID: uuid.NewString()}
	claims.Subject = userID.String()
	rec := httptest.NewRecorder()
	h.AcceptDocument(rec, draftRequest(http.MethodPost, `{"doc_type":"TERMS_OF_SERVICE","doc_version":"3"}`, claims, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
	}
	if st, _ := h.userConsentState(ctx, userID, &signedUp, DocTypeTermsOfService, now); st.required != nil {
		t.Fatalf("still required after accepting: %v", st.required.Version)
	}

	// A material version announced for later shows as upcoming, not required.
	seedPolicyVersion(t, client, DocTypeTermsOfService, "4", now.Add(20*day), true)
	st, _ = h.userConsentState(ctx, userID, &signedUp, DocTypeTermsOfService, now)
	if st.required != nil || st.upcoming == nil || st.upcoming.Version != "4" {
		t.Fatalf("upcoming material version: required=%v upcoming=%v", st.required, st.upcoming)
	}
}

// One draft per type; a non-dated draft becomes the only current version when published; a draft
// can be discarded but a published version cannot; the overview reports it all.
func TestLegalPolicies_DraftsAndOverview(t *testing.T) {
	client := newLegalTestClient(t)
	h := NewLegalHandler(client, nil, zap.NewNop())
	ctx := context.Background()
	admin := &token.Claims{IsPlatformOwner: true, Email: "owner@example.com"}

	if _, err := client.LegalDocument.Create().SetDocType("MSA").SetVersion("v1.0").SetHTMLContent("<p>old</p>").
		SetEffectiveDate(time.Now().Add(-48 * time.Hour)).SetIsCurrent(true).Save(ctx); err != nil {
		t.Fatalf("seed MSA: %v", err)
	}
	v2 := map[string]string{"type": "MSA", "version": "v2.0"}
	rec := httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>new</p>","title":"Master Services Agreement","summary":"Clearer fees"}`, admin, v2))
	if rec.Code != http.StatusCreated {
		t.Fatalf("MSA draft: %d %s", rec.Code, rec.Body.String())
	}
	if b := decodeBody(t, rec); b["title"] != "Master Services Agreement" || b["updated_by"] != "owner@example.com" {
		t.Fatalf("draft metadata: %v", b)
	}
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>other</p>"}`, admin, map[string]string{"type": "MSA", "version": "v3.0"}))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "draft_exists") {
		t.Fatalf("second draft: %d %s", rec.Code, rec.Body.String())
	}

	// Published with no date: current now, the old version no longer current.
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{}`, admin, v2))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish MSA: %d %s", rec.Code, rec.Body.String())
	}
	n, _ := client.LegalDocument.Query().Where(legaldocument.DocTypeEQ("MSA"), legaldocument.IsCurrentEQ(true)).Count(ctx)
	cur, _ := client.LegalDocument.Query().Where(legaldocument.DocTypeEQ("MSA"), legaldocument.IsCurrentEQ(true)).First(ctx)
	if n != 1 || cur == nil || cur.Version != "v2.0" || cur.Metadata["published_by"] != "owner@example.com" {
		t.Fatalf("after publish: %d current, %+v", n, cur)
	}

	// Skip notice with no date puts an effective-dated policy in force now.
	pv := map[string]string{"type": "privacy-policy", "version": "1"}
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>privacy</p>"}`, admin, pv))
	if rec.Code != http.StatusCreated {
		t.Fatalf("privacy draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.PublishDraft(rec, draftRequest(http.MethodPost, `{"skip_notice":true,"material":true}`, admin, pv))
	if b := decodeBody(t, rec); rec.Code != http.StatusOK || b["in_force"] != true || b["material"] != true {
		t.Fatalf("privacy skip-notice publish: %d %s", rec.Code, rec.Body.String())
	}

	// Discard: a draft goes, a published version stays.
	cv := map[string]string{"type": "cookie-policy", "version": "1"}
	rec = httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>cookies</p>","material":true}`, admin, cv))
	if rec.Code != http.StatusCreated {
		t.Fatalf("cookie draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.DiscardDraft(rec, draftRequest(http.MethodDelete, "", admin, cv))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("discard: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.DiscardDraft(rec, draftRequest(http.MethodDelete, "", admin, v2))
	if rec.Code != http.StatusConflict {
		t.Fatalf("discard a published version: %d, want 409", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.AdminOverview(rec, authedGet("/", admin))
	docs, _ := decodeBody(t, rec)["documents"].([]any)
	if rec.Code != http.StatusOK || len(docs) != len(allDocTypes) {
		t.Fatalf("overview: %d %s", rec.Code, rec.Body.String())
	}
	states := map[string]string{}
	for _, d := range docs {
		m := d.(map[string]any)
		for _, v := range m["versions"].([]any) {
			vm := v.(map[string]any)
			states[m["doc_type"].(string)+"/"+vm["version"].(string)] = vm["state"].(string)
		}
	}
	if states["MSA/v2.0"] != "current" || states["MSA/v1.0"] != "superseded" || states["PRIVACY_POLICY/1"] != "current" {
		t.Fatalf("overview states: %v", states)
	}
}

func authedGet(target string, claims *token.Claims) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(authmiddleware.ContextWithClaims(req.Context(), claims))
}
