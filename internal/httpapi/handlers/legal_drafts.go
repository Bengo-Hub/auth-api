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

// draftDocType reads {type}. Every type has drafts since the dashboard manages them all (owner
// 2026-11-15): an effective-dated draft is published with its date, any other draft becomes the
// current version when published.
func draftDocType(w http.ResponseWriter, r *http.Request) (string, bool) {
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return "", false
	}
	return docType, true
}

// legalActor names the admin making a change for the version's record: the email in the token,
// else the user id.
func legalActor(r *http.Request) string {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		return ""
	}
	if claims.Email != "" {
		return claims.Email
	}
	return claims.Subject
}

// maxLegalTitle and maxLegalSummary bound the editorial fields kept in metadata.
const (
	maxLegalTitle   = 200
	maxLegalSummary = 2000
)

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
// draft. A published version is never turned back into a draft: 409 version_published. A type
// keeps one draft at a time, as in Hadia: a second version while another is a draft is 409
// draft_exists, naming it.
// PUT /api/v1/admin/legal/documents/{type}/drafts/{version}
// Body: { "html_content": "...", "effective_date": "YYYY-MM-DD" (optional proposal),
//
//	"title": "...", "summary": "what changed", "material": false }
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
		Title         string `json:"title"`
		Summary       string `json:"summary"`
		Material      *bool  `json:"material"`
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
	req.Title, req.Summary = strings.TrimSpace(req.Title), strings.TrimSpace(req.Summary)
	if len(req.Title) > maxLegalTitle || len(req.Summary) > maxLegalSummary {
		writeError(w, http.StatusBadRequest, "invalid_metadata", "title is up to 200 characters and summary up to 2,000", nil)
		return
	}
	meta := map[string]any{"title": req.Title, "summary": req.Summary, "updated_by": legalActor(r)}
	if req.Material != nil {
		meta["material"] = *req.Material
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
			SetMetadata(withMetadata(existing.Metadata, meta)).
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
		other, oerr := h.ent.LegalDocument.Query().
			Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), legaldocument.StatusEQ(legaldocument.StatusDraft)).
			First(ctx)
		if oerr != nil && !ent.IsNotFound(oerr) {
			h.logger.Error("failed to check for an open legal document draft", zap.Error(oerr))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to save draft", nil)
			return
		}
		if other != nil {
			writeError(w, http.StatusConflict, "draft_exists",
				"this document already has a draft; edit or discard it first",
				map[string]any{"doc_type": docType, "draft_version": other.Version})
			return
		}
		doc, err = h.ent.LegalDocument.Create().
			SetDocType(legaldocument.DocType(docType)).
			SetVersion(version).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			SetIsCurrent(false).
			SetStatus(legaldocument.StatusDraft).
			SetMetadata(withMetadata(nil, meta)).
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
		Summary       string `json:"summary"`
		Material      *bool  `json:"material"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	now := time.Now()
	dated := isEffectiveDated(docType)
	var effDate time.Time
	switch {
	case strings.TrimSpace(req.EffectiveDate) != "":
		d, perr := parseEffectiveDate(req.EffectiveDate)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "invalid_date", "effective_date must be YYYY-MM-DD or RFC 3339", nil)
			return
		}
		effDate = d
	case !dated || req.SkipNotice:
		// Skipping the notice with no date means "in force now" (the owner's 2026-11-15 publish
		// stayed upcoming because the form kept the proposed date). A non-dated document is
		// current from the moment it is published. Truncated to the second: Postgres keeps
		// microseconds and rounds, so an untruncated now can be stored just after itself and
		// read back as upcoming.
		effDate = now.Truncate(time.Second)
	default:
		writeError(w, http.StatusBadRequest, "invalid_date", "effective_date is required, YYYY-MM-DD or RFC 3339", nil)
		return
	}
	if dated && !h.checkNotice(w, docType, effDate, req.SkipNotice, now) {
		return
	}
	req.Summary = strings.TrimSpace(req.Summary)
	if len(req.Summary) > maxLegalSummary {
		writeError(w, http.StatusBadRequest, "invalid_metadata", "summary is up to 2,000 characters", nil)
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
	meta := map[string]any{"summary": req.Summary, "published_by": legalActor(r), "published_at": now.UTC().Format(time.RFC3339)}
	if req.Material != nil {
		meta["material"] = *req.Material
	}
	if !isUserConsent(docType) {
		// Only Terms of Service and Privacy Policy changes ask users to accept again.
		meta["material"] = false
	}

	// One transaction: the publish, and for a non-dated type the is_current switch, land together.
	tx, err := h.ent.Tx(ctx)
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to publish draft", nil)
		return
	}
	// The status condition makes a second publish (a double click, two admins) a no-op 409.
	n, err := tx.LegalDocument.Update().
		Where(legaldocument.IDEQ(draft.ID), legaldocument.StatusEQ(legaldocument.StatusDraft)).
		SetStatus(legaldocument.StatusPublished).
		SetEffectiveDate(effDate).
		SetIsCurrent(!dated).
		SetMetadata(withMetadata(draft.Metadata, meta)).
		Save(ctx)
	if err == nil && n > 0 && !dated {
		err = tx.LegalDocument.Update().
			Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), legaldocument.IDNEQ(draft.ID)).
			SetIsCurrent(false).
			Exec(ctx)
	}
	if err != nil {
		_ = tx.Rollback()
		h.logger.Error("failed to publish legal document draft", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to publish draft", nil)
		return
	}
	if n == 0 {
		_ = tx.Rollback()
		writeError(w, http.StatusConflict, "already_published", "this version was published meanwhile",
			map[string]any{"doc_type": docType, "version": version})
		return
	}
	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit legal document publish", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to publish draft", nil)
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
	// A material Terms of Service or Privacy Policy version is emailed to every user.
	h.startChangeNotice(doc)
	writeJSON(w, http.StatusOK, legalDocJSON(doc, now, false))
}
