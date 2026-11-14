package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		"list":    h.AdminListVersions,
		"get":     h.AdminGetVersion,
		"save":    h.SaveDraft,
		"publish": h.PublishDraft,
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

	// Drafts exist only for the effective-dated types.
	rec := httptest.NewRecorder()
	h.SaveDraft(rec, draftRequest(http.MethodPut, `{"html_content":"<p>x</p>"}`, admin, map[string]string{"type": "MSA", "version": "1"}))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "drafts_not_supported") {
		t.Fatalf("MSA draft: %d %s", rec.Code, rec.Body.String())
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

func authedGet(target string, claims *token.Claims) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return req.WithContext(authmiddleware.ContextWithClaims(req.Context(), claims))
}
