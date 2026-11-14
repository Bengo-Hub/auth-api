package handlers

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// Draft versions of effective-dated legal documents (owner 2026-11-14). The platform admin saves
// a version as a draft, reads it back on auth-ui's preview page and publishes it with its
// effective date, under the same minimum notice and skip_notice rule as a direct publish. A
// draft is invisible to every public read and to acceptance (see isPublished). Once published it
// follows the published rules: editable through UpsertDocument until it is in force or accepted,
// then fixed.

// draftVersionRE keeps a draft's version usable as a URL segment (auth-ui reads
// /legal/marketflow-autopublish-terms/preview/{version}).
var draftVersionRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// maxLegalHTMLBytes bounds a draft body. The longest document today is well under 100 KB.
const maxLegalHTMLBytes = 1 << 20

// requireLegalAdmin answers 401 or 403 unless the caller is a platform admin.
func requireLegalAdmin(w http.ResponseWriter, r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return false
	}
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return false
	}
	return true
}

// draftDocType reads {type} and allows only the effective-dated types, the only ones with drafts.
func draftDocType(w http.ResponseWriter, r *http.Request) (string, bool) {
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return "", false
	}
	if !isEffectiveDated(docType) {
		writeError(w, http.StatusBadRequest, "drafts_not_supported",
			"drafts are kept only for effective-dated documents", map[string]any{"doc_type": docType})
		return "", false
	}
	return docType, true
}

func draftVersion(w http.ResponseWriter, r *http.Request) (string, bool) {
	version := strings.TrimSpace(chi.URLParam(r, "version"))
	if !draftVersionRE.MatchString(version) {
		writeError(w, http.StatusBadRequest, "invalid_version",
			"version is 1 to 32 letters, digits, dots, dashes or underscores", nil)
		return "", false
	}
	return version, true
}

// noticeJSON tells the admin UI what the publish form must respect.
func (h *LegalHandler) noticeJSON(docType string, now time.Time) map[string]any {
	notice := h.minNotice(docType)
	return map[string]any{
		"min_notice_days": int(notice.Hours() / 24),
		"earliest":        now.Add(notice).UTC().Format(time.RFC3339),
	}
}

// proposedEffectiveDate is the date stored on a draft saved without one: the first midnight UTC
// that still gives the minimum notice from now. It is only a proposal; publishing sets the date.
func proposedEffectiveDate(now time.Time, notice time.Duration) time.Time {
	t := now.Add(notice).UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if day.Before(t) {
		day = day.AddDate(0, 0, 1)
	}
	return day
}

// AdminListVersions lists every version of a type, drafts included, newest first, without bodies.
// ?status=draft or ?status=published narrows it.
// GET /api/v1/admin/legal/documents/{type}/versions
func (h *LegalHandler) AdminListVersions(w http.ResponseWriter, r *http.Request) {
	if !requireLegalAdmin(w, r) {
		return
	}
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	q := h.ent.LegalDocument.Query().Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)))
	switch s := strings.TrimSpace(r.URL.Query().Get("status")); s {
	case "":
	case string(legaldocument.StatusDraft), string(legaldocument.StatusPublished):
		q = q.Where(legaldocument.StatusEQ(legaldocument.Status(s)))
	default:
		writeError(w, http.StatusBadRequest, "invalid_status", "status must be draft or published", nil)
		return
	}
	docs, err := q.Order(ent.Desc(legaldocument.FieldEffectiveDate), ent.Desc(legaldocument.FieldCreatedAt)).All(r.Context())
	if err != nil {
		h.logger.Error("failed to list legal document versions for admin", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list versions", nil)
		return
	}
	now := time.Now()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		out = append(out, legalDocJSON(d, now, false))
	}
	resp := map[string]any{"doc_type": docType, "versions": out}
	if isEffectiveDated(docType) {
		resp["notice"] = h.noticeJSON(docType, now)
	}
	writeJSON(w, http.StatusOK, resp)
}

// AdminGetVersion returns one version with its body for the admin preview, draft or published,
// with the notice the publish form must respect.
// GET /api/v1/admin/legal/documents/{type}/versions/{version}
func (h *LegalHandler) AdminGetVersion(w http.ResponseWriter, r *http.Request) {
	if !requireLegalAdmin(w, r) {
		return
	}
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	version := strings.TrimSpace(chi.URLParam(r, "version"))
	doc, err := h.ent.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), legaldocument.VersionEQ(version)).
		First(r.Context())
	if ent.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "no such version", map[string]any{"doc_type": docType, "version": version})
		return
	}
	if err != nil {
		h.logger.Error("failed to fetch legal document version for admin", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to fetch document", nil)
		return
	}
	now := time.Now()
	resp := legalDocJSON(doc, now, true)
	if isEffectiveDated(docType) {
		resp["notice"] = h.noticeJSON(docType, now)
	}
	writeJSON(w, http.StatusOK, resp)
}

// SaveDraft creates a draft version or replaces the body (and the proposed date) of an existing
// draft. A published version is never turned back into a draft: 409 version_published.
// PUT /api/v1/admin/legal/documents/{type}/drafts/{version}
// Body: { "html_content": "...", "effective_date": "YYYY-MM-DD" (optional proposal) }
func (h *LegalHandler) SaveDraft(w http.ResponseWriter, r *http.Request) {
	if !requireLegalAdmin(w, r) {
		return
	}
	docType, ok := draftDocType(w, r)
	if !ok {
		return
	}
	version, ok := draftVersion(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLegalHTMLBytes+64<<10)
	var req struct {
		HtmlContent   string `json:"html_content"`
		EffectiveDate string `json:"effective_date"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	if strings.TrimSpace(req.HtmlContent) == "" {
		writeError(w, http.StatusBadRequest, "invalid_content", "html_content is required", nil)
		return
	}
	if len(req.HtmlContent) > maxLegalHTMLBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "content_too_large", "html_content must be at most 1 MB", nil)
		return
	}
	now := time.Now()
	effDate := proposedEffectiveDate(now, h.minNotice(docType))
	if strings.TrimSpace(req.EffectiveDate) != "" {
		d, err := parseEffectiveDate(req.EffectiveDate)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_date", "effective_date must be YYYY-MM-DD or RFC 3339", nil)
			return
		}
		effDate = d
	}

	ctx := r.Context()
	existing, err := h.ent.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), legaldocument.VersionEQ(version)).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		h.logger.Error("failed to read legal document draft", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save draft", nil)
		return
	}

	var doc *ent.LegalDocument
	status := http.StatusOK
	switch {
	case existing != nil && existing.Status != legaldocument.StatusDraft:
		writeError(w, http.StatusConflict, "version_published",
			"this version is already published; a change is a new version",
			map[string]any{"doc_type": docType, "version": version})
		return
	case existing != nil:
		// Only a row that is still a draft is changed, so a publish that lands meanwhile wins.
		n, uerr := h.ent.LegalDocument.Update().
			Where(legaldocument.IDEQ(existing.ID), legaldocument.StatusEQ(legaldocument.StatusDraft)).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			Save(ctx)
		if uerr == nil && n == 0 {
			writeError(w, http.StatusConflict, "version_published",
				"this version was published meanwhile; a change is a new version",
				map[string]any{"doc_type": docType, "version": version})
			return
		}
		if uerr == nil {
			doc, uerr = h.ent.LegalDocument.Get(ctx, existing.ID)
		}
		err = uerr
	default:
		doc, err = h.ent.LegalDocument.Create().
			SetDocType(legaldocument.DocType(docType)).
			SetVersion(version).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			SetIsCurrent(false).
			SetStatus(legaldocument.StatusDraft).
			Save(ctx)
		if ent.IsConstraintError(err) {
			writeError(w, http.StatusConflict, "version_exists", "this version was created meanwhile; try again", nil)
			return
		}
		status = http.StatusCreated
	}
	if err != nil {
		h.logger.Error("failed to save legal document draft", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save draft", nil)
		return
	}
	h.logger.Info("legal document draft saved", zap.String("doc_type", docType), zap.String("version", version))
	resp := legalDocJSON(doc, now, false)
	resp["notice"] = h.noticeJSON(docType, now)
	writeJSON(w, status, resp)
}

// PublishDraft publishes a draft with its effective date. The minimum notice applies as on a
// direct publish (skip_notice overrides it for an urgent legal change or a first version the owner
// approved). From then on the version is public and follows the published rules.
// POST /api/v1/admin/legal/documents/{type}/drafts/{version}/publish
// Body: { "effective_date": "YYYY-MM-DD", "skip_notice": false }
func (h *LegalHandler) PublishDraft(w http.ResponseWriter, r *http.Request) {
	if !requireLegalAdmin(w, r) {
		return
	}
	docType, ok := draftDocType(w, r)
	if !ok {
		return
	}
	version, ok := draftVersion(w, r)
	if !ok {
		return
	}
	var req struct {
		EffectiveDate string `json:"effective_date"`
		SkipNotice    bool   `json:"skip_notice"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	effDate, err := parseEffectiveDate(req.EffectiveDate)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_date", "effective_date is required, YYYY-MM-DD or RFC 3339", nil)
		return
	}
	now := time.Now()
	if !h.checkNotice(w, docType, effDate, req.SkipNotice, now) {
		return
	}

	ctx := r.Context()
	draft, err := h.ent.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), legaldocument.VersionEQ(version)).
		Only(ctx)
	if ent.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "no such draft", map[string]any{"doc_type": docType, "version": version})
		return
	}
	if err != nil {
		h.logger.Error("failed to read legal document draft", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to publish draft", nil)
		return
	}
	if draft.Status != legaldocument.StatusDraft {
		writeError(w, http.StatusConflict, "already_published", "this version is already published",
			map[string]any{"doc_type": docType, "version": version})
		return
	}
	if strings.TrimSpace(draft.HTMLContent) == "" {
		writeError(w, http.StatusBadRequest, "invalid_content", "the draft has no body", nil)
		return
	}
	// The status condition makes a second publish (a double click, two admins) a no-op 409.
	n, err := h.ent.LegalDocument.Update().
		Where(legaldocument.IDEQ(draft.ID), legaldocument.StatusEQ(legaldocument.StatusDraft)).
		SetStatus(legaldocument.StatusPublished).
		SetEffectiveDate(effDate).
		SetIsCurrent(false).
		Save(ctx)
	if err != nil {
		h.logger.Error("failed to publish legal document draft", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to publish draft", nil)
		return
	}
	if n == 0 {
		writeError(w, http.StatusConflict, "already_published", "this version was published meanwhile",
			map[string]any{"doc_type": docType, "version": version})
		return
	}
	doc, err := h.ent.LegalDocument.Get(ctx, draft.ID)
	if err != nil {
		h.logger.Error("failed to read published legal document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "published, but failed to read it back", nil)
		return
	}
	h.logger.Info("legal document draft published",
		zap.String("doc_type", docType), zap.String("version", version),
		zap.Time("effective_date", effDate), zap.Bool("skip_notice", req.SkipNotice))
	writeJSON(w, http.StatusOK, legalDocJSON(doc, now, false))
}
