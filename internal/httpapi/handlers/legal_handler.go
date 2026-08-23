package handlers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

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
	logger *zap.Logger
}

func NewLegalHandler(entClient *ent.Client, logger *zap.Logger) *LegalHandler {
	return &LegalHandler{ent: entClient, logger: logger.Named("legal")}
}

// GetCurrentDocument returns the current version of a legal document (public).
// GET /api/v1/legal/documents/{type}
func (h *LegalHandler) GetCurrentDocument(w http.ResponseWriter, r *http.Request) {
	docType := chi.URLParam(r, "type")
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, DPA, or RESELLER_AGREEMENT", nil)
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
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}
	if !isValidDocType(req.DocType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, DPA, or RESELLER_AGREEMENT", nil)
		return
	}
	effDate, err := time.Parse(time.DateOnly, req.EffectiveDate)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_date", "effective_date must be YYYY-MM-DD", nil)
		return
	}

	ctx := r.Context()

	// If this version already exists, update it; otherwise create.
	existing, _ := h.ent.LegalDocument.Query().
		Where(
			legaldocument.DocTypeEQ(legaldocument.DocType(req.DocType)),
			legaldocument.VersionEQ(req.Version),
		).Only(ctx)

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

	writeJSON(w, http.StatusOK, map[string]any{
		"id":       doc.ID.String(),
		"doc_type": string(doc.DocType),
		"version":  doc.Version,
		"current":  doc.IsCurrent,
	})
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
	if !isValidDocType(req.DocType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, DPA, or RESELLER_AGREEMENT", nil)
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
		return
	}

	acceptance, err := h.ent.LegalAcceptance.Create().
		SetEntityID(tenantID).
		SetEntityType("tenant").
		SetDocType(legalacceptance.DocType(req.DocType)).
		SetDocVersion(req.DocVersion).
		SetAcceptedAt(time.Now()).
		SetIPAddress(clientIP(r)).
		SetUserAgent(userAgent(r)).
		Save(r.Context())
	if err != nil {
		h.logger.Error("failed to record legal acceptance", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to record acceptance", nil)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          acceptance.ID.String(),
		"doc_type":    acceptance.DocType,
		"version":     acceptance.DocVersion,
		"accepted_at": acceptance.AcceptedAt.Format(time.RFC3339),
	})
}

// parseSignatureUpload extracts and validates a multipart signature_image upload (jpg/png,
// ≤2MB) shared by SignDocument and SignDocumentAsEquityHolder. On failure it writes the
// response itself and returns ok=false — callers should just return.
func parseSignatureUpload(w http.ResponseWriter, r *http.Request) (docType, docVersion, dataURL string, ok bool) {
	const maxSize = 2 << 20 // 2 MB
	if err := r.ParseMultipartForm(maxSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_form", "failed to parse form (max 2MB)", nil)
		return "", "", "", false
	}

	docType = r.FormValue("doc_type")
	docVersion = r.FormValue("doc_version")
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, DPA, or RESELLER_AGREEMENT", nil)
		return "", "", "", false
	}

	file, header, err := r.FormFile("signature_image")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing_file", "signature_image file is required", nil)
		return "", "", "", false
	}
	defer file.Close()

	ct := header.Header.Get("Content-Type")
	if ct != "image/jpeg" && ct != "image/jpg" && ct != "image/png" {
		writeError(w, http.StatusBadRequest, "invalid_file_type", "signature_image must be jpg or png", nil)
		return "", "", "", false
	}

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_error", "failed to read file", nil)
		return "", "", "", false
	}
	if int64(len(data)) > maxSize {
		writeError(w, http.StatusRequestEntityTooLarge, "file_too_large", "signature_image must be ≤ 2MB", nil)
		return "", "", "", false
	}

	dataURL = fmt.Sprintf("data:%s;base64,%s", ct, base64.StdEncoding.EncodeToString(data))
	return docType, docVersion, dataURL, true
}

// SignDocument accepts a multipart upload of a signature image (jpg/png ≤ 2MB)
// and stores the base64 data URL in the legal_acceptance record.
// POST /api/v1/auth/legal/sign
// Form fields: doc_type, doc_version, signature_image (file)
func (h *LegalHandler) SignDocument(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}

	docType, docVersion, dataURL, ok := parseSignatureUpload(w, r)
	if !ok {
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
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
		SetSignatureImageURL(dataURL).
		Save(r.Context())
	if err != nil {
		h.logger.Error("failed to persist signed document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save signature", nil)
		return
	}

	h.logger.Info("document signed",
		zap.String("tenant_id", tenantID.String()),
		zap.String("doc_type", docType),
		zap.String("acceptance_id", acceptance.ID.String()),
	)

	writeJSON(w, http.StatusCreated, map[string]any{
		"acceptance_id":       acceptance.ID.String(),
		"doc_type":            acceptance.DocType,
		"signed_at":           acceptance.AcceptedAt.Format(time.RFC3339),
		"signature_image_url": acceptance.SignatureImageURL,
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
	return t == "EPA" || t == "MSA" || t == "DPA" || t == "RESELLER_AGREEMENT"
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
