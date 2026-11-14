package handlers

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Bengo-Hub/httpware/objectstore"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/equityholderapplication"
	"github.com/bengobox/auth-api/internal/ent/legalacceptance"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/platform/outbox"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// LegalHandler handles legal document management and acceptance (EPA/MSA/DPA).
type LegalHandler struct {
	ent    *ent.Client
	media  *objectstore.Store // signature images, private
	logger *zap.Logger
	// noticeDefault and noticeByType are the minimum notice of an effective-dated version
	// (config LEGAL_MIN_NOTICE_DAYS and LEGAL_MIN_NOTICE_DAYS_BY_TYPE; 14 days unless set).
	noticeDefault time.Duration
	noticeByType  map[string]time.Duration
}

func NewLegalHandler(entClient *ent.Client, media *objectstore.Store, logger *zap.Logger) *LegalHandler {
	return &LegalHandler{ent: entClient, media: media, logger: logger.Named("legal"), noticeDefault: defaultMinNotice}
}

// maxSignatureBytes keeps the limit signature uploads always had.
const maxSignatureBytes = 2 << 20

// RegisterLegalMediaTypes sets the signature rules (private, JPEG or PNG, re-encoded, 2 MB) on the
// shared registry. Call once at startup.
func RegisterLegalMediaTypes() {
	objectstore.Register(objectstore.MediaType{Name: objectstore.TypeSignatures, MaxBytes: maxSignatureBytes,
		Allowed: []string{"image/jpeg", "image/png"}, Image: true})
}

// GetCurrentDocument returns the current version of a legal document (public).
// GET /api/v1/legal/documents/{type}
func (h *LegalHandler) GetCurrentDocument(w http.ResponseWriter, r *http.Request) {
	docType := normalizeDocType(chi.URLParam(r, "type"))
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	if isEffectiveDated(docType) {
		h.getEffectiveDated(w, r, docType)
		return
	}

	// Read the newest current version rather than Only(): Only() returns
	// *ent.NotSingularError (a 500, not a 404) if the is_current flag was ever
	// left on two rows, which would take the public document endpoint down
	// permanently. UpsertDocument now flips is_current transactionally so that
	// cannot happen, but a pre-existing bad row must still serve traffic.
	docs, err := h.ent.LegalDocument.Query().
		Where(
			legaldocument.DocTypeEQ(legaldocument.DocType(docType)),
			legaldocument.IsCurrentEQ(true),
		).
		Order(
			ent.Desc(legaldocument.FieldEffectiveDate),
			ent.Desc(legaldocument.FieldCreatedAt),
		).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to fetch legal document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to fetch document", nil)
		return
	}
	if len(docs) == 0 {
		writeError(w, http.StatusNotFound, "not_found", "no current document found for type "+docType, nil)
		return
	}
	if len(docs) > 1 {
		h.logger.Error("multiple current legal documents for doc_type; serving newest",
			zap.String("doc_type", docType), zap.Int("count", len(docs)))
	}
	doc := docs[0]

	writeJSON(w, http.StatusOK, map[string]any{
		"id":             doc.ID.String(),
		"doc_type":       string(doc.DocType),
		"version":        doc.Version,
		"html_content":   doc.HTMLContent,
		"effective_date": doc.EffectiveDate.Format(time.DateOnly),
	})
}

// UpsertDocument creates or updates a legal document (admin only).
// POST /api/v1/admin/legal/documents
func (h *LegalHandler) UpsertDocument(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	// The EPA/MSA/DPA bodies are platform-wide legal instruments, not tenant data:
	// gate on platform admin, never on a tenant-scoped admin/superuser role.
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	var req struct {
		DocType       string `json:"doc_type"`
		Version       string `json:"version"`
		HtmlContent   string `json:"html_content"`
		EffectiveDate string `json:"effective_date"`
		SetCurrent    bool   `json:"set_current"`
		// SkipNotice lets an effective-dated version start sooner than its type's minimum
		// notice (14 days for the MarketFlow auto-publish terms). Meant for a first version
		// that no tenant has accepted anything before, or a correction the owner approved.
		SkipNotice bool `json:"skip_notice"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	req.DocType = normalizeDocType(req.DocType)
	req.Version = strings.TrimSpace(req.Version)
	if !isValidDocType(req.DocType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}
	if req.Version == "" || len(req.Version) > 32 {
		writeError(w, http.StatusBadRequest, "invalid_version", "version is required, up to 32 characters", nil)
		return
	}
	effDate, err := parseEffectiveDate(req.EffectiveDate)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_date", "effective_date must be YYYY-MM-DD or RFC 3339", nil)
		return
	}

	ctx := r.Context()
	now := time.Now()
	dated := isEffectiveDated(req.DocType)
	if dated {
		// An effective-dated version is in force by its date, never by the is_current flag.
		req.SetCurrent = false
		if strings.TrimSpace(req.HtmlContent) == "" {
			writeError(w, http.StatusBadRequest, "invalid_content", "html_content is required", nil)
			return
		}
		if notice := h.minNotice(req.DocType); notice > 0 && !req.SkipNotice && effDate.Before(now.Add(notice)) {
			writeError(w, http.StatusBadRequest, "notice_too_short",
				"effective_date must give tenants the minimum notice; send skip_notice to override",
				map[string]any{"min_notice_days": int(notice.Hours() / 24), "earliest": now.Add(notice).UTC().Format(time.RFC3339)})
			return
		}
	}

	// If this version already exists, update it; otherwise create.
	existing, _ := h.ent.LegalDocument.Query().
		Where(
			legaldocument.DocTypeEQ(legaldocument.DocType(req.DocType)),
			legaldocument.VersionEQ(req.Version),
		).Only(ctx)

	// A version that has come into force is what tenants were bound by: editing it in place
	// would change the record of what applied. Publish a new version instead.
	if dated && existing != nil && !existing.EffectiveDate.After(now) {
		writeError(w, http.StatusConflict, "document_in_force",
			"this version is already in force and is immutable; publish a new version instead",
			map[string]any{"doc_type": req.DocType, "version": req.Version})
		return
	}

	// A document version that anyone has already signed/accepted is immutable: the
	// legal_acceptance row is evidence of consent to THAT body of text, so editing
	// html_content in place would silently rewrite an executed agreement (e.g. the
	// EPA an equity holder signed). Publish a new version instead.
	if existing != nil {
		accepted, accErr := h.ent.LegalAcceptance.Query().
			Where(
				legalacceptance.DocTypeEQ(legalacceptance.DocType(req.DocType)),
				legalacceptance.DocVersionEQ(req.Version),
			).
			Exist(ctx)
		if accErr != nil {
			h.logger.Error("failed to check legal acceptances", zap.Error(accErr))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to validate document", nil)
			return
		}
		if accepted {
			writeError(w, http.StatusConflict, "document_already_accepted",
				"this document version has already been accepted and is immutable; publish a new version instead",
				map[string]any{"doc_type": req.DocType, "version": req.Version})
			return
		}
	}

	// The write and the is_current flip must be atomic: a partial failure between
	// them leaves two rows flagged current for one doc_type, which breaks the
	// public GetCurrentDocument read for every consumer.
	tx, err := h.ent.Tx(ctx)
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save document", nil)
		return
	}

	var doc *ent.LegalDocument
	if existing != nil {
		doc, err = tx.LegalDocument.UpdateOneID(existing.ID).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			SetIsCurrent(req.SetCurrent).
			Save(ctx)
	} else {
		doc, err = tx.LegalDocument.Create().
			SetDocType(legaldocument.DocType(req.DocType)).
			SetVersion(req.Version).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			SetIsCurrent(req.SetCurrent).
			Save(ctx)
	}
	if err != nil {
		_ = tx.Rollback()
		h.logger.Error("failed to upsert legal document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save document", nil)
		return
	}

	// If set_current, clear is_current on all other versions of this doc_type.
	if req.SetCurrent {
		if err := tx.LegalDocument.Update().
			Where(
				legaldocument.DocTypeEQ(legaldocument.DocType(req.DocType)),
				legaldocument.IDNEQ(doc.ID),
			).
			SetIsCurrent(false).
			Exec(ctx); err != nil {
			_ = tx.Rollback()
			h.logger.Error("failed to clear previous current legal document", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to save document", nil)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit legal document upsert", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save document", nil)
		return
	}

	resp := map[string]any{
		"id":       doc.ID.String(),
		"doc_type": string(doc.DocType),
		"version":  doc.Version,
		"current":  doc.IsCurrent,
	}
	if dated {
		resp["current"] = !doc.EffectiveDate.After(now)
		resp["effective_at"] = doc.EffectiveDate.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

// AcceptDocument records a legal document acceptance (authed).
// POST /api/v1/auth/legal/accept
// Body: { "doc_type": "DPA", "doc_version": "v1.0" }
func (h *LegalHandler) AcceptDocument(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}

	var req struct {
		DocType    string `json:"doc_type"`
		DocVersion string `json:"doc_version"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	req.DocType = normalizeDocType(req.DocType)
	if !isValidDocType(req.DocType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
		return
	}
	var userID *uuid.UUID
	if id, err := uuid.Parse(claims.Subject); err == nil {
		userID = &id
	}

	h.recordAcceptance(w, r, acceptanceInput{
		TenantID: tenantID, UserID: userID, DocType: req.DocType, Version: req.DocVersion,
		IP: clientIP(r), UserAgent: userAgent(r),
	})
}

// parseSignatureUpload extracts and validates a multipart signature_image upload (JPEG or PNG
// checked from the bytes, up to 2 MB, re-encoded) and stores it privately at
// auth/<tenant>/signatures/<uuid>.<ext>, returning the key. On failure it writes the response
// itself and returns ok=false; callers should just return.
func (h *LegalHandler) parseSignatureUpload(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (docType, docVersion, key string, ok bool) {
	const maxSize = maxSignatureBytes
	if !h.media.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "storage_unavailable", "file storage is not configured", nil)
		return "", "", "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSize+64<<10)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_form", "failed to parse form (max 2MB)", nil)
		return "", "", "", false
	}

	docType = normalizeDocType(r.FormValue("doc_type"))
	docVersion = r.FormValue("doc_version")
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", invalidDocTypeMessage, nil)
		return "", "", "", false
	}

	file, header, err := r.FormFile("signature_image")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing_file", "signature_image file is required", nil)
		return "", "", "", false
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_error", "failed to read file", nil)
		return "", "", "", false
	}
	if int64(len(data)) > maxSize {
		writeError(w, http.StatusRequestEntityTooLarge, "file_too_large", "signature_image must be at most 2 MB", nil)
		return "", "", "", false
	}
	// The type comes from the bytes (the client's Content-Type is not trusted).
	up, err := objectstore.Prepare(data, objectstore.TypeSignatures)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_file_type", "signature_image must be a JPEG or PNG image", nil)
		return "", "", "", false
	}
	key, err = h.media.NewKey(objectstore.Owner{TenantID: tenantID.String()}, objectstore.TypeSignatures, up.Ext)
	if err == nil {
		err = h.media.Put(r.Context(), key, up.Data, up.ContentType)
	}
	if err != nil {
		h.logger.Error("store signature failed", zap.Error(err), zap.String("file", header.Filename))
		writeError(w, http.StatusBadGateway, "storage_error", "failed to store the signature", nil)
		return "", "", "", false
	}
	return docType, docVersion, key, true
}

// SignDocument accepts a multipart upload of a signature image (jpg/png ≤ 2MB)
// and keeps its private object storage key in the legal_acceptance record.
// POST /api/v1/auth/legal/sign
// Form fields: doc_type, doc_version, signature_image (file)
func (h *LegalHandler) SignDocument(w http.ResponseWriter, r *http.Request) {
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

	docType, docVersion, key, ok := h.parseSignatureUpload(w, r, tenantID)
	if !ok {
		return
	}

	acceptance, err := h.ent.LegalAcceptance.Create().
		SetEntityID(tenantID).
		SetEntityType(legalacceptance.EntityTypeTenant).
		SetDocType(legalacceptance.DocType(docType)).
		SetDocVersion(docVersion).
		SetAcceptedAt(time.Now()).
		SetIPAddress(clientIP(r)).
		SetUserAgent(userAgent(r)).
		SetSignatureImageURL(key).
		Save(r.Context())
	if err != nil {
		_ = h.media.Delete(r.Context(), key)
		h.logger.Error("failed to persist signed document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save signature", nil)
		return
	}

	h.logger.Info("document signed",
		zap.String("tenant_id", tenantID.String()),
		zap.String("doc_type", docType),
		zap.String("acceptance_id", acceptance.ID.String()),
	)

	// The signature is private: a short-lived presigned link (the row keeps the key).
	writeJSON(w, http.StatusCreated, map[string]any{
		"acceptance_id":       acceptance.ID.String(),
		"doc_type":            acceptance.DocType,
		"signed_at":           acceptance.AcceptedAt.Format(time.RFC3339),
		"signature_image_url": h.media.URL(acceptance.SignatureImageURL),
	})
}

// ─── Equity Holder Applications ───────────────────────────────────────────────

// CreateApplication creates an equity holder application for the current tenant.
// POST /api/v1/auth/equity/apply
func (h *LegalHandler) CreateApplication(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Notes string `json:"notes"`
	}
	_ = decodeJSON(r, &req)

	app, err := h.ent.EquityHolderApplication.Create().
		SetTenantID(tenantID).
		SetStatus(equityholderapplication.StatusPending).
		SetNotes(req.Notes).
		Save(r.Context())
	if err != nil {
		h.logger.Error("failed to create equity application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create application", nil)
		return
	}
	writeJSON(w, http.StatusCreated, toApplicationResponse(app))
}

// ListApplications returns all equity holder applications (admin only).
// GET /api/v1/admin/equity/applications
func (h *LegalHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	// Unscoped cross-tenant read: every applicant's kyc_reference (a Smile Identity
	// job id) is in this response, so it must be platform-admin only. A tenant
	// wanting its own application should get a separate /auth-prefixed endpoint
	// scoped by claims.TenantID rather than a filter bolted onto this one.
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	apps, err := h.ent.EquityHolderApplication.Query().
		Order(ent.Desc(equityholderapplication.FieldCreatedAt)).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to list equity applications", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list applications", nil)
		return
	}
	resp := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		resp = append(resp, toApplicationResponse(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"applications": resp})
}

// UpdateApplication updates an equity application status (admin only).
// PUT /api/v1/admin/equity/applications/{id}
func (h *LegalHandler) UpdateApplication(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	// Setting status=approved emits auth.equity_holder_application.approved, which
	// treasury-api consumes to auto-create a revenue-sharing equity holder. Without
	// this gate ANY authenticated user could approve their own application and mint
	// themselves a real payout entitlement.
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid application id", nil)
		return
	}

	var req struct {
		Status           string `json:"status"`
		Notes            string `json:"notes"`
		KYCReference     string `json:"kyc_reference"`
		TreasuryHolderID string `json:"treasury_holder_id"`
		EPAAcceptanceID  string `json:"epa_acceptance_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}

	ctx := r.Context()

	current, err := h.ent.EquityHolderApplication.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "application not found", nil)
			return
		}
		h.logger.Error("failed to load equity application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	if req.Status != "" {
		if vErr := equityholderapplication.StatusValidator(equityholderapplication.Status(req.Status)); vErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_status", "unknown application status: "+req.Status, nil)
			return
		}
		// Idempotency guard: a repeated PUT with the status the application already
		// holds is rejected rather than re-emitting the domain event. Re-sending
		// status=approved otherwise queues a second
		// auth.equity_holder_application.approved event and treasury-api would
		// create a duplicate equity holder.
		if string(current.Status) == req.Status {
			writeError(w, http.StatusConflict, "status_unchanged",
				"application is already in status "+req.Status,
				map[string]any{"application_id": id.String(), "status": req.Status})
			return
		}
	}

	// The status write and the outbox event are committed together — a status change
	// that is visible without its event (or an event without the status change)
	// desynchronises treasury-api from auth-api permanently.
	tx, err := h.ent.Tx(ctx)
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	upd := tx.EquityHolderApplication.UpdateOneID(id)
	if req.Status != "" {
		upd.SetStatus(equityholderapplication.Status(req.Status))
	}
	if req.Notes != "" {
		upd.SetNotes(req.Notes)
	}
	if req.KYCReference != "" {
		upd.SetKycReference(req.KYCReference)
	}
	if req.TreasuryHolderID != "" {
		if tid, err := uuid.Parse(req.TreasuryHolderID); err == nil {
			upd.SetTreasuryHolderID(tid)
		}
	}
	if req.EPAAcceptanceID != "" {
		if eid, err := uuid.Parse(req.EPAAcceptanceID); err == nil {
			upd.SetEpaAcceptanceID(eid)
		}
	}

	app, err := upd.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "application not found", nil)
			return
		}
		h.logger.Error("failed to update equity application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	// Emit a domain event on status change so downstream services can react. The
	// "approved" event in particular carries enough context for treasury-api to auto-create
	// the equity holder (closing the previously-manual handoff) once KYC + EPA are complete.
	// Written through tx.Client() (not the best-effort writeOutboxEvent helper) so a
	// failed enqueue rolls the status change back instead of being logged and dropped.
	if req.Status != "" {
		payload := map[string]any{
			"application_id": app.ID.String(),
			"tenant_id":      app.TenantID.String(),
			"status":         string(app.Status),
		}
		if app.EpaAcceptanceID != nil {
			payload["epa_acceptance_id"] = app.EpaAcceptanceID.String()
			// Surface the signed EPA version so treasury can record which agreement governs the holder.
			if acc, accErr := tx.LegalAcceptance.Get(ctx, *app.EpaAcceptanceID); accErr == nil {
				payload["epa_doc_version"] = acc.DocVersion
				payload["epa_accepted_at"] = acc.AcceptedAt.Format(time.RFC3339)
			}
		}
		if app.TreasuryHolderID != nil {
			payload["treasury_holder_id"] = app.TreasuryHolderID.String()
		}
		eventType := "status_updated"
		if app.Status == equityholderapplication.StatusApproved {
			eventType = "approved"
		}
		if evErr := outbox.Write(ctx, tx.Client(), app.TenantID,
			"auth.equity_holder_application", app.ID, eventType, "", payload); evErr != nil {
			_ = tx.Rollback()
			h.logger.Error("failed to enqueue equity application event",
				zap.String("event_type", eventType), zap.Error(evErr))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit equity application update", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	writeJSON(w, http.StatusOK, toApplicationResponse(app))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func isValidDocType(t string) bool {
	return legaldocument.DocTypeValidator(legaldocument.DocType(t)) == nil
}

func toApplicationResponse(a *ent.EquityHolderApplication) map[string]any {
	r := map[string]any{
		"id":         a.ID.String(),
		"tenant_id":  a.TenantID.String(),
		"status":     string(a.Status),
		"notes":      a.Notes,
		"created_at": a.CreatedAt.Format(time.RFC3339),
		"updated_at": a.UpdatedAt.Format(time.RFC3339),
	}
	if a.KycReference != "" {
		r["kyc_reference"] = a.KycReference
	}
	if a.TreasuryHolderID != nil {
		r["treasury_holder_id"] = a.TreasuryHolderID.String()
	}
	if a.EpaAcceptanceID != nil {
		r["epa_acceptance_id"] = a.EpaAcceptanceID.String()
	}
	return r
}
