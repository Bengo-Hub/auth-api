package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/legalacceptance"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Dashboard-managed legal documents (owner 2026-11-15, modelled on Hadia's legal module). The
// platform admin sees every document on one page with its version in force, the upcoming one,
// the open draft and the history; edits a draft; and publishes it. A material change to the Terms
// of Service or the Privacy Policy asks every user to accept it again (PendingConsents). A
// version that a newer one replaced is "superseded"; that state is derived from the timeline,
// never stored.

// AdminOverview lists every document type with its state, without bodies.
// GET /api/v1/admin/legal/overview
func (h *LegalHandler) AdminOverview(w http.ResponseWriter, r *http.Request) {
	if !requireLegalAdmin(w, r) {
		return
	}
	ctx := r.Context()
	// One query for every version of every type; the table holds a few dozen rows.
	docs, err := h.ent.LegalDocument.Query().
		Order(ent.Desc(legaldocument.FieldEffectiveDate), ent.Desc(legaldocument.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		h.logger.Error("failed to list legal documents for the overview", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list documents", nil)
		return
	}
	byType := map[string][]*ent.LegalDocument{}
	for _, d := range docs {
		byType[string(d.DocType)] = append(byType[string(d.DocType)], d)
	}
	now := time.Now()
	out := make([]map[string]any, 0, len(allDocTypes))
	for _, t := range allDocTypes {
		out = append(out, h.overviewEntry(t, byType[t], now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": out})
}

// overviewEntry builds one type's state from its versions, newest effective date first.
func (h *LegalHandler) overviewEntry(docType string, versions []*ent.LegalDocument, now time.Time) map[string]any {
	dated := isEffectiveDated(docType)
	var current, upcoming, draft *ent.LegalDocument
	for _, d := range versions {
		switch {
		case d.Status == legaldocument.StatusDraft:
			if draft == nil {
				draft = d
			}
		case dated && d.EffectiveDate.After(now):
			upcoming = d // newest first, so the last one seen is the earliest upcoming
		case dated:
			if current == nil {
				current = d
			}
		case d.IsCurrent && current == nil:
			current = d
		}
	}
	history := make([]map[string]any, 0, len(versions))
	for _, d := range versions {
		v := legalDocJSON(d, now, false)
		v["state"] = versionState(d, current, upcoming, now)
		history = append(history, v)
	}
	entry := map[string]any{
		"doc_type":        docType,
		"kind":            docTypeKind(docType),
		"effective_dated": dated,
		"current":         nil,
		"upcoming":        nil,
		"draft":           nil,
		"versions":        history,
	}
	if current != nil {
		entry["current"] = legalDocJSON(current, now, false)
	}
	if upcoming != nil {
		entry["upcoming"] = legalDocJSON(upcoming, now, false)
	}
	if draft != nil {
		entry["draft"] = legalDocJSON(draft, now, false)
	}
	if dated {
		entry["notice"] = h.noticeJSON(docType, now)
	}
	return entry
}

// versionState is draft, current, upcoming, scheduled (a later upcoming one), or superseded.
func versionState(d, current, upcoming *ent.LegalDocument, now time.Time) string {
	switch {
	case d.Status == legaldocument.StatusDraft:
		return "draft"
	case current != nil && d.ID == current.ID:
		return "current"
	case upcoming != nil && d.ID == upcoming.ID:
		return "upcoming"
	case isEffectiveDated(string(d.DocType)) && d.EffectiveDate.After(now):
		return "scheduled"
	default:
		return "superseded"
	}
}

// DiscardDraft deletes a draft. A published version is never deleted: 409.
// DELETE /api/v1/admin/legal/documents/{type}/drafts/{version}
func (h *LegalHandler) DiscardDraft(w http.ResponseWriter, r *http.Request) {
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
	n, err := h.ent.LegalDocument.Delete().
		Where(
			legaldocument.DocTypeEQ(legaldocument.DocType(docType)),
			legaldocument.VersionEQ(version),
			legaldocument.StatusEQ(legaldocument.StatusDraft),
		).
		Exec(r.Context())
	if err != nil {
		h.logger.Error("failed to discard legal document draft", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to discard draft", nil)
		return
	}
	if n == 0 {
		writeError(w, http.StatusConflict, "not_a_draft", "no draft with this version; a published version is kept",
			map[string]any{"doc_type": docType, "version": version})
		return
	}
	h.logger.Info("legal document draft discarded", zap.String("doc_type", docType), zap.String("version", version),
		zap.String("by", legalActor(r)))
	w.WriteHeader(http.StatusNoContent)
}

// consentState is what one user still has to accept for one consent type.
type consentState struct {
	required *ent.LegalDocument // the version in force, when a material change in force is not yet accepted
	upcoming *ent.LegalDocument // a material version announced for later, not yet accepted
}

// userConsentState works out, for one consent type, whether the user owes an acceptance.
//
// The user's sign-up acceptance (users.terms_accepted_at) covers every version in force when
// they signed up, so only a material version that came into force after that asks again. Any
// acceptance of that version or a later one settles it.
func (h *LegalHandler) userConsentState(ctx context.Context, userID uuid.UUID, signedUpAccept *time.Time, docType string, now time.Time) (consentState, error) {
	var st consentState
	versions, err := h.ent.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), isPublished).
		Order(ent.Desc(legaldocument.FieldEffectiveDate), ent.Desc(legaldocument.FieldCreatedAt)).
		All(ctx)
	if err != nil || len(versions) == 0 {
		return st, err
	}
	accepted := map[string]bool{}
	rows, err := h.ent.LegalAcceptance.Query().
		Where(
			legalacceptance.EntityIDEQ(userID),
			legalacceptance.EntityTypeEQ(legalacceptance.EntityTypeUser),
			legalacceptance.DocTypeEQ(legalacceptance.DocType(docType)),
		).
		All(ctx)
	if err != nil {
		return st, err
	}
	for _, a := range rows {
		accepted[a.DocVersion] = true
	}
	// Walk newest first. Anything accepted at or after a version settles it and everything older.
	settled := false
	for _, v := range versions {
		if accepted[v.Version] {
			settled = true
		}
		if settled {
			break
		}
		if !docMaterial(v) {
			continue
		}
		if v.EffectiveDate.After(now) {
			if st.upcoming == nil || v.EffectiveDate.Before(st.upcoming.EffectiveDate) {
				st.upcoming = v
			}
			continue
		}
		if signedUpAccept != nil && !signedUpAccept.Before(v.EffectiveDate) {
			break // they signed up under this version or a later one
		}
		st.required = v
		break
	}
	if st.required != nil {
		// Only the version in force (or the upcoming one) can be accepted, and accepting it
		// settles the older material change too, so that is the one the user is asked for.
		for _, v := range versions {
			if !v.EffectiveDate.After(now) {
				st.required = v
				break
			}
		}
	}
	return st, nil
}

// PendingConsents lists the Terms of Service and Privacy Policy versions the signed-in user must
// accept (required: in force, material, not accepted) or will have to (upcoming). auth-ui shows a
// banner from it and the user accepts through POST /auth/legal/accept.
// GET /api/v1/auth/legal/pending
func (h *LegalHandler) PendingConsents(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id in token", nil)
		return
	}
	ctx := r.Context()
	u, err := h.ent.User.Get(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		h.logger.Error("failed to read user for pending consents", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to read pending consents", nil)
		return
	}
	now := time.Now()
	required := []map[string]any{}
	upcoming := []map[string]any{}
	for _, t := range []string{DocTypeTermsOfService, DocTypePrivacyPolicy} {
		st, err := h.userConsentState(ctx, userID, u.TermsAcceptedAt, t, now)
		if err != nil {
			h.logger.Error("failed to work out pending consent", zap.String("doc_type", t), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to read pending consents", nil)
			return
		}
		if st.required != nil {
			required = append(required, legalDocJSON(st.required, now, false))
		}
		if st.upcoming != nil {
			upcoming = append(upcoming, legalDocJSON(st.upcoming, now, false))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"required": required, "upcoming": upcoming})
}
