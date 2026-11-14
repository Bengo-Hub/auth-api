package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/legalacceptance"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Versioned, effective-dated legal documents (owner 2026-11-14). The MarketFlow Autopilot
// auto-publish terms are the first: a version is created by the platform admin with its
// effective date, it is announced as "upcoming" until that date, and from then it is the
// version in force. Tenants accept a version (current or upcoming) and products read which
// versions a tenant accepted, through the user's own token or the S2S routes.

// DocTypeMarketFlowAutoPublishTerms is the MarketFlow Autopilot auto-publish (veto window) terms.
const DocTypeMarketFlowAutoPublishTerms = "MARKETFLOW_AUTOPUBLISH_TERMS"

// Platform policies managed from the dashboard (owner 2026-11-15).
const (
	DocTypeTermsOfService = "TERMS_OF_SERVICE"
	DocTypePrivacyPolicy  = "PRIVACY_POLICY"
	DocTypeCookiePolicy   = "COOKIE_POLICY"
	DocTypeRefundPolicy   = "REFUND_POLICY"
	DocTypeDataRequests   = "DATA_REQUESTS"
)

const invalidDocTypeMessage = "doc_type must be EPA, MSA, DPA, RESELLER_AGREEMENT, MARKETFLOW_AUTOPUBLISH_TERMS, " +
	"TERMS_OF_SERVICE, PRIVACY_POLICY, COOKIE_POLICY, REFUND_POLICY or DATA_REQUESTS"

// effectiveDatedDocTypes are the types whose version in force follows effective_date.
var effectiveDatedDocTypes = map[string]bool{
	DocTypeMarketFlowAutoPublishTerms: true,
	DocTypeTermsOfService:             true,
	DocTypePrivacyPolicy:              true,
	DocTypeCookiePolicy:               true,
	DocTypeRefundPolicy:               true,
	DocTypeDataRequests:               true,
}

func isEffectiveDated(docType string) bool { return effectiveDatedDocTypes[docType] }

// userConsentDocTypes are accepted by each user for themselves; a material version asks every
// user to accept it again (see PendingConsents).
var userConsentDocTypes = map[string]bool{
	DocTypeTermsOfService: true,
	DocTypePrivacyPolicy:  true,
}

func isUserConsent(docType string) bool { return userConsentDocTypes[docType] }

// noticeOnlyDocTypes are published for information; nobody accepts them.
var noticeOnlyDocTypes = map[string]bool{
	DocTypeCookiePolicy: true,
	DocTypeRefundPolicy: true,
	DocTypeDataRequests: true,
}

// tenantProductTerms are effective-dated terms a tenant accepts for a product, which a product
// service may record for a user it has authorised (S2SAcceptForTenant).
var tenantProductTerms = map[string]bool{
	DocTypeMarketFlowAutoPublishTerms: true,
}

// docTypeKind tells the admin dashboard how a type behaves.
func docTypeKind(docType string) string {
	switch {
	case isUserConsent(docType):
		return "user_consent"
	case noticeOnlyDocTypes[docType]:
		return "notice"
	case tenantProductTerms[docType]:
		return "product_terms"
	default:
		return "agreement"
	}
}

// allDocTypes is every type in the order the dashboard lists them.
var allDocTypes = []string{
	DocTypeTermsOfService, DocTypePrivacyPolicy, DocTypeCookiePolicy, DocTypeRefundPolicy, DocTypeDataRequests,
	DocTypeMarketFlowAutoPublishTerms, "MSA", "DPA", "EPA", "RESELLER_AGREEMENT",
}

// defaultMinNotice is the notice a new effective-dated version gives when config sets none
// (owner 2026-11-14: 14 days).
const defaultMinNotice = 14 * 24 * time.Hour

// WithMinNotice sets the minimum notice from config: defaultDays for every effective-dated type
// (0 or more; a negative value keeps 14 days) and byType as "TYPE=days,..." overrides. Entries
// that do not parse are skipped.
func (h *LegalHandler) WithMinNotice(defaultDays int, byType string) *LegalHandler {
	if defaultDays >= 0 {
		h.noticeDefault = time.Duration(defaultDays) * 24 * time.Hour
	}
	h.noticeByType = parseNoticeByType(byType)
	return h
}

func parseNoticeByType(s string) map[string]time.Duration {
	out := map[string]time.Duration{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		days, err := strconv.Atoi(strings.TrimSpace(v))
		docType := normalizeDocType(k)
		if err != nil || days < 0 || !isValidDocType(docType) {
			continue
		}
		out[docType] = time.Duration(days) * 24 * time.Hour
	}
	return out
}

// minNotice is the notice a new version of docType must give; 0 for a type that is not
// effective-dated.
func (h *LegalHandler) minNotice(docType string) time.Duration {
	if !isEffectiveDated(docType) {
		return 0
	}
	if d, ok := h.noticeByType[docType]; ok {
		return d
	}
	return h.noticeDefault
}

// checkNotice refuses (400 notice_too_short) an effective date that gives less than the type's
// minimum notice, unless skip is set. It writes the response itself and returns false then.
func (h *LegalHandler) checkNotice(w http.ResponseWriter, docType string, effDate time.Time, skip bool, now time.Time) bool {
	notice := h.minNotice(docType)
	if notice <= 0 || skip || !effDate.Before(now.Add(notice)) {
		return true
	}
	writeError(w, http.StatusBadRequest, "notice_too_short",
		"effective_date must give tenants the minimum notice; send skip_notice to override",
		map[string]any{"min_notice_days": int(notice.Hours() / 24), "earliest": now.Add(notice).UTC().Format(time.RFC3339)})
	return false
}

// normalizeDocType accepts the URL form too: "marketflow-autopublish-terms" is
// MARKETFLOW_AUTOPUBLISH_TERMS.
func normalizeDocType(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "_"))
}

// parseEffectiveDate reads YYYY-MM-DD (midnight UTC) or an RFC 3339 time.
func parseEffectiveDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// isPublished is the filter every public read and every acceptance check uses: a draft is never
// shown, never current or upcoming and never accepted.
var isPublished = legaldocument.StatusEQ(legaldocument.StatusPublished)

// docTimeline returns the published version in force at now (newest effective_date not after now)
// and the next published version announced after it (earliest effective_date after now). Either
// may be nil.
func docTimeline(ctx context.Context, client *ent.Client, docType string, now time.Time) (current, upcoming *ent.LegalDocument, err error) {
	current, err = client.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), isPublished, legaldocument.EffectiveDateLTE(now)).
		Order(ent.Desc(legaldocument.FieldEffectiveDate), ent.Desc(legaldocument.FieldCreatedAt)).
		First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, nil, err
	}
	upcoming, err = client.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), isPublished, legaldocument.EffectiveDateGT(now)).
		Order(ent.Asc(legaldocument.FieldEffectiveDate), ent.Asc(legaldocument.FieldCreatedAt)).
		First(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, nil, err
	}
	return current, upcoming, nil
}

// legalDocJSON is one version; withBody adds the HTML.
func legalDocJSON(doc *ent.LegalDocument, now time.Time, withBody bool) map[string]any {
	m := map[string]any{
		"id":             doc.ID.String(),
		"doc_type":       string(doc.DocType),
		"version":        doc.Version,
		"effective_date": doc.EffectiveDate.UTC().Format(time.DateOnly),
		"effective_at":   doc.EffectiveDate.UTC().Format(time.RFC3339),
		"status":         string(doc.Status),
	}
	if doc.Status == legaldocument.StatusDraft {
		// A draft's date is only a proposal; the date is set when it is published.
		m["in_force"] = false
	} else if isEffectiveDated(string(doc.DocType)) {
		m["in_force"] = !doc.EffectiveDate.After(now)
	} else {
		m["is_current"] = doc.IsCurrent
	}
	for _, k := range []string{"title", "summary", "updated_by", "published_by", "published_at"} {
		if v, ok := doc.Metadata[k].(string); ok && v != "" {
			m[k] = v
		}
	}
	m["material"] = docMaterial(doc)
	if withBody {
		m["html_content"] = doc.HTMLContent
	}
	return m
}

// docMaterial reports whether a version is a material change users must accept again.
func docMaterial(doc *ent.LegalDocument) bool {
	v, _ := doc.Metadata["material"].(bool)
	return v
}

// withMetadata returns a copy of base with the given non-empty values set, so a stored map is
// never changed in place.
func withMetadata(base map[string]any, set map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(set))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range set {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// getEffectiveDated answers GET /legal/documents/{type} for an effective-dated type: the version in
// force (also flattened at the top level, like the other types) and the upcoming one, each with
// its body. 404 only when no version was ever published.
func (h *LegalHandler) getEffectiveDated(w http.ResponseWriter, r *http.Request, docType string) {
	now := time.Now()
	current, upcoming, err := docTimeline(r.Context(), h.ent, docType, now)
	if err != nil {
		h.logger.Error("failed to fetch legal document timeline", zap.String("doc_type", docType), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to fetch document", nil)
		return
	}
	if current == nil && upcoming == nil {
		writeError(w, http.StatusNotFound, "not_found", "no version published for type "+docType, nil)
		return
	}
	resp := map[string]any{"doc_type": docType, "current": nil, "upcoming": nil}
	if current != nil {
		for k, v := range legalDocJSON(current, now, true) {
			resp[k] = v
		}
		resp["current"] = legalDocJSON(current, now, true)
	}
	if upcoming != nil {
		resp["upcoming"] = legalDocJSON(upcoming, now, true)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ListDocumentVersions lists every published version of a type, newest first, without bodies (public).
// GET /api/v1/legal/documents/{type}/versions
func (h *LegalHandler) ListDocumentVersions(w http.ResponseWriter, r *http.Request) {
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	docs, err := h.ent.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), isPublished).
		Order(ent.Desc(legaldocument.FieldEffectiveDate), ent.Desc(legaldocument.FieldCreatedAt)).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to list legal document versions", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list versions", nil)
		return
	}
	now := time.Now()
	out := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		out = append(out, legalDocJSON(d, now, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"doc_type": docType, "versions": out})
}

// GetDocumentVersion returns one version with its body (public), including an upcoming one, so
// tenants can read new terms during their notice period.
// GET /api/v1/legal/documents/{type}/versions/{version}
func (h *LegalHandler) GetDocumentVersion(w http.ResponseWriter, r *http.Request) {
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	version := strings.TrimSpace(chi.URLParam(r, "version"))
	doc, err := h.ent.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType)), legaldocument.VersionEQ(version), isPublished).
		First(r.Context())
	if ent.IsNotFound(err) {
		// A draft answers exactly like a version that does not exist.
		writeError(w, http.StatusNotFound, "not_found", "no such version", map[string]any{"doc_type": docType, "version": version})
		return
	}
	if err != nil {
		h.logger.Error("failed to fetch legal document version", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to fetch document", nil)
		return
	}
	writeJSON(w, http.StatusOK, legalDocJSON(doc, time.Now(), true))
}

// acceptanceInput is one tenant acceptance, from the user's own token or an S2S caller.
type acceptanceInput struct {
	TenantID  uuid.UUID
	UserID    *uuid.UUID
	DocType   string
	Version   string
	IP        string
	UserAgent string
}

// recordAcceptance validates and stores an acceptance and writes the response: 201 when recorded,
// 200 with the earlier row when this tenant already accepted the same version (idempotent). For
// an effective-dated type the version must be the one in force or the upcoming one.
//
// Terms of Service and the Privacy Policy are accepted by the user for themselves (entity user);
// every other acceptable type is accepted for the tenant. Cookie, refund and data request notices
// are not accepted at all.
func (h *LegalHandler) recordAcceptance(w http.ResponseWriter, r *http.Request, in acceptanceInput) {
	ctx := r.Context()
	in.Version = strings.TrimSpace(in.Version)
	if in.Version == "" || len(in.Version) > 32 {
		writeError(w, http.StatusBadRequest, "invalid_version", "doc_version is required, up to 32 characters", nil)
		return
	}
	if noticeOnlyDocTypes[in.DocType] {
		writeError(w, http.StatusBadRequest, "not_acceptable", "this document is a notice and is not accepted",
			map[string]any{"doc_type": in.DocType})
		return
	}
	entityID, entityType := in.TenantID, legalacceptance.EntityTypeTenant
	if isUserConsent(in.DocType) {
		if in.UserID == nil {
			writeError(w, http.StatusBadRequest, "user_required", "this document is accepted by a signed-in user", nil)
			return
		}
		entityID, entityType = *in.UserID, legalacceptance.EntityTypeUser
	}
	if isEffectiveDated(in.DocType) {
		current, upcoming, err := docTimeline(ctx, h.ent, in.DocType, time.Now())
		if err != nil {
			h.logger.Error("failed to read legal document timeline", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to record acceptance", nil)
			return
		}
		ok := (current != nil && current.Version == in.Version) || (upcoming != nil && upcoming.Version == in.Version)
		if !ok {
			details := map[string]any{"doc_type": in.DocType, "version": in.Version}
			if current != nil {
				details["current_version"] = current.Version
			}
			if upcoming != nil {
				details["upcoming_version"] = upcoming.Version
			}
			writeError(w, http.StatusConflict, "version_not_acceptable",
				"only the version in force or the upcoming version can be accepted", details)
			return
		}
		prior, err := h.ent.LegalAcceptance.Query().
			Where(
				legalacceptance.EntityIDEQ(entityID),
				legalacceptance.EntityTypeEQ(entityType),
				legalacceptance.DocTypeEQ(legalacceptance.DocType(in.DocType)),
				legalacceptance.DocVersionEQ(in.Version),
			).
			Order(ent.Asc(legalacceptance.FieldAcceptedAt)).
			First(ctx)
		if err == nil {
			writeJSON(w, http.StatusOK, acceptanceJSON(prior))
			return
		}
		if !ent.IsNotFound(err) {
			h.logger.Error("failed to read legal acceptances", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to record acceptance", nil)
			return
		}
	}

	create := h.ent.LegalAcceptance.Create().
		SetEntityID(entityID).
		SetEntityType(entityType).
		SetDocType(legalacceptance.DocType(in.DocType)).
		SetDocVersion(in.Version).
		SetAcceptedAt(time.Now()).
		SetIPAddress(truncate(in.IP, 64)).
		SetUserAgent(truncate(in.UserAgent, 512))
	if in.UserID != nil {
		create.SetAcceptedByUserID(*in.UserID)
	}
	acceptance, err := create.Save(ctx)
	if err != nil {
		h.logger.Error("failed to record legal acceptance", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to record acceptance", nil)
		return
	}
	writeJSON(w, http.StatusCreated, acceptanceJSON(acceptance))
}

func acceptanceJSON(a *ent.LegalAcceptance) map[string]any {
	m := map[string]any{
		"id":          a.ID.String(),
		"doc_type":    string(a.DocType),
		"version":     a.DocVersion,
		"accepted_at": a.AcceptedAt.UTC().Format(time.RFC3339),
		"signed":      a.SignatureImageURL != "",
	}
	if a.AcceptedByUserID != nil {
		m["accepted_by_user_id"] = a.AcceptedByUserID.String()
	}
	return m
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// listTenantAcceptances writes a tenant's acceptances, newest first, optionally of one doc_type.
func (h *LegalHandler) listTenantAcceptances(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	q := h.ent.LegalAcceptance.Query().
		Where(legalacceptance.EntityIDEQ(tenantID), legalacceptance.EntityTypeEQ(legalacceptance.EntityTypeTenant))
	if raw := r.URL.Query().Get("doc_type"); raw != "" {
		docType := normalizeDocType(raw)
		if !isValidDocType(docType) {
			writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
			return
		}
		q = q.Where(legalacceptance.DocTypeEQ(legalacceptance.DocType(docType)))
	}
	rows, err := q.Order(ent.Desc(legalacceptance.FieldAcceptedAt)).Limit(200).All(r.Context())
	if err != nil {
		h.logger.Error("failed to list legal acceptances", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list acceptances", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, acceptanceJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant_id": tenantID.String(), "acceptances": out})
}

// ListMyAcceptances returns the caller's tenant's acceptances (authed).
// GET /api/v1/auth/legal/acceptances?doc_type=MARKETFLOW_AUTOPUBLISH_TERMS
func (h *LegalHandler) ListMyAcceptances(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
		return
	}
	h.listTenantAcceptances(w, r, tenantID)
}

// S2SListTenantAcceptances returns a tenant's acceptances to a product service (internal key).
// GET /api/v1/s2s/tenants/{tenant_id}/legal/acceptances?doc_type=MARKETFLOW_AUTOPUBLISH_TERMS
func (h *LegalHandler) S2SListTenantAcceptances(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "tenant_id must be a UUID", nil)
		return
	}
	h.listTenantAcceptances(w, r, tenantID)
}

// S2SAcceptForTenant records an acceptance a product service took from a signed-in user it has
// already authorised (MarketFlow checks the approving roles). The caller passes the user and the
// browser's address and user agent, which are stored as given.
// POST /api/v1/s2s/tenants/{tenant_id}/legal/acceptances
// Body: { "doc_type", "doc_version", "user_id", "ip_address", "user_agent" }
func (h *LegalHandler) S2SAcceptForTenant(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "tenant_id must be a UUID", nil)
		return
	}
	var req struct {
		DocType    string `json:"doc_type"`
		DocVersion string `json:"doc_version"`
		UserID     string `json:"user_id"`
		IPAddress  string `json:"ip_address"`
		UserAgent  string `json:"user_agent"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	docType := normalizeDocType(req.DocType)
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	// A service records only product terms; the platform agreements (EPA, MSA, DPA, reseller) and
	// the user's own Terms of Service and Privacy Policy consent are given by the signed-in user.
	if !tenantProductTerms[docType] {
		writeError(w, http.StatusForbidden, "forbidden", "this document type cannot be accepted by a service", nil)
		return
	}
	var userID *uuid.UUID
	if req.UserID != "" {
		id, err := uuid.Parse(req.UserID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_user", "user_id must be a UUID", nil)
			return
		}
		userID = &id
	}
	h.recordAcceptance(w, r, acceptanceInput{
		TenantID: tenantID, UserID: userID, DocType: docType, Version: req.DocVersion,
		IP: req.IPAddress, UserAgent: req.UserAgent,
	})
}
