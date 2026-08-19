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
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, or DPA", nil)
		return
	}

	doc, err := h.ent.LegalDocument.Query().
		Where(
			legaldocument.DocTypeEQ(legaldocument.DocType(docType)),
			legaldocument.IsCurrentEQ(true),
		).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "no current document found for type "+docType, nil)
			return
		}
		h.logger.Error("failed to fetch legal document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to fetch document", nil)
		return
	}

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
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, or DPA", nil)
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

	var doc *ent.LegalDocument
	if existing != nil {
		doc, err = h.ent.LegalDocument.UpdateOneID(existing.ID).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			SetIsCurrent(req.SetCurrent).
			Save(ctx)
	} else {
		doc, err = h.ent.LegalDocument.Create().
			SetDocType(legaldocument.DocType(req.DocType)).
			SetVersion(req.Version).
			SetHTMLContent(req.HtmlContent).
			SetEffectiveDate(effDate).
			SetIsCurrent(req.SetCurrent).
			Save(ctx)
	}
	if err != nil {
		h.logger.Error("failed to upsert legal document", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to save document", nil)
		return
	}

	// If set_current, clear is_current on all other versions of this doc_type.
	if req.SetCurrent {
		_ = h.ent.LegalDocument.Update().
			Where(
				legaldocument.DocTypeEQ(legaldocument.DocType(req.DocType)),
				legaldocument.IDNEQ(doc.ID),
			).
			SetIsCurrent(false).
			Exec(ctx)
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
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, or DPA", nil)
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

	const maxSize = 2 << 20 // 2 MB
	if err := r.ParseMultipartForm(maxSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_form", "failed to parse form (max 2MB)", nil)
		return
	}

	docType := r.FormValue("doc_type")
	docVersion := r.FormValue("doc_version")
	if !isValidDocType(docType) {
		writeError(w, http.StatusBadRequest, "invalid_doc_type", "doc_type must be EPA, MSA, or DPA", nil)
		return
	}

	file, header, err := r.FormFile("signature_image")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing_file", "signature_image file is required", nil)
		return
	}
	defer file.Close()

	ct := header.Header.Get("Content-Type")
	if ct != "image/jpeg" && ct != "image/jpg" && ct != "image/png" {
		writeError(w, http.StatusBadRequest, "invalid_file_type", "signature_image must be jpg or png", nil)
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_error", "failed to read file", nil)
		return
	}
	if int64(len(data)) > maxSize {
		writeError(w, http.StatusRequestEntityTooLarge, "file_too_large", "signature_image must be ≤ 2MB", nil)
		return
	}

	dataURL := fmt.Sprintf("data:%s;base64,%s", ct, base64.StdEncoding.EncodeToString(data))

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "invalid tenant ID in token", nil)
		return
	}

	acceptance, err := h.ent.LegalAcceptance.Create().
		SetEntityID(tenantID).
		SetEntityType("tenant").
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

	upd := h.ent.EquityHolderApplication.UpdateOneID(id)
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

	app, err := upd.Save(r.Context())
	if err != nil {
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
	if req.Status != "" {
		payload := map[string]any{
			"application_id": app.ID.String(),
			"tenant_id":      app.TenantID.String(),
			"status":         string(app.Status),
		}
		if app.EpaAcceptanceID != nil {
			payload["epa_acceptance_id"] = app.EpaAcceptanceID.String()
			// Surface the signed EPA version so treasury can record which agreement governs the holder.
			if acc, accErr := h.ent.LegalAcceptance.Get(r.Context(), *app.EpaAcceptanceID); accErr == nil {
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
		writeOutboxEvent(r.Context(), h.ent, h.logger, app.TenantID,
			"auth.equity_holder_application", app.ID, eventType, payload)
	}

	writeJSON(w, http.StatusOK, toApplicationResponse(app))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func isValidDocType(t string) bool {
	return t == "EPA" || t == "MSA" || t == "DPA"
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
