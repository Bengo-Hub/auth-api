package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/integrationrequest"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// IntegrationRequestHandler manages the request/review workflow for enabling a platform
// integration (starting with eTIMS) for a tenant or an external lead, and fires the Slack/email
// support notification on every new request.
type IntegrationRequestHandler struct {
	ent      *ent.Client
	notifier *EtimsSupportNotifier
	logger   *zap.Logger
}

func NewIntegrationRequestHandler(entClient *ent.Client, notifier *EtimsSupportNotifier, logger *zap.Logger) *IntegrationRequestHandler {
	return &IntegrationRequestHandler{ent: entClient, notifier: notifier, logger: logger}
}

type createIntegrationRequestBody struct {
	RequestType     string `json:"request_type"`
	RequesterName   string `json:"requester_name"`
	RequesterEmail  string `json:"requester_email"`
	RequesterPhone  string `json:"requester_phone"`
	CompanyName     string `json:"company_name"`
	KraPin          string `json:"kra_pin"`
	IntegrationMode string `json:"integration_mode"`
	Notes           string `json:"notes"`
}

// CreateIntegrationRequest handles POST /api/v1/integration-requests. JWT is optional: when
// present, the request is tied to the caller's own tenant (the onboarded-tenant path); when
// absent, it's an anonymous/public submission (rate-limited at the router level) — though the
// primary external-lead intake is codevertex-website's own Lead capture calling the sibling S2S
// notify-only endpoint below, not this one.
func (h *IntegrationRequestHandler) CreateIntegrationRequest(w http.ResponseWriter, r *http.Request) {
	var body createIntegrationRequestBody
	if err := decodeJSON(r, &body); err != nil || body.RequesterName == "" || body.RequesterEmail == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "requester_name and requester_email are required", nil)
		return
	}
	if body.RequestType == "" {
		body.RequestType = "etims_integration"
	}
	mode := integrationrequest.IntegrationMode(body.IntegrationMode)
	if mode != integrationrequest.IntegrationModeSelfServe && mode != integrationrequest.IntegrationModeAssisted {
		mode = integrationrequest.IntegrationModeSelfServe
	}

	create := h.ent.IntegrationRequest.Create().
		SetRequestType(body.RequestType).
		SetRequesterName(body.RequesterName).
		SetRequesterEmail(body.RequesterEmail).
		SetRequesterPhone(body.RequesterPhone).
		SetCompanyName(body.CompanyName).
		SetKraPin(body.KraPin).
		SetIntegrationMode(mode).
		SetNotes(body.Notes).
		SetSource(integrationrequest.SourceTenantPortal)

	var tenantID string
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims.TenantID != "" {
		if tid, err := uuid.Parse(claims.TenantID); err == nil {
			create.SetTenantID(tid)
			tenantID = tid.String()
		}
	} else {
		create.SetSource(integrationrequest.SourcePublicWebsite)
	}

	rec, err := create.Save(r.Context())
	if err != nil {
		h.logger.Error("create integration request", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create request", nil)
		return
	}

	if h.notifier != nil {
		go h.notifier.Notify(context.WithoutCancel(r.Context()), EtimsSupportNotification{
			RequestType:     body.RequestType,
			IntegrationMode: string(mode),
			CompanyName:     body.CompanyName,
			RequesterName:   body.RequesterName,
			RequesterEmail:  body.RequesterEmail,
			RequesterPhone:  body.RequesterPhone,
			TenantID:        tenantID,
			Source:          string(rec.Source),
			Notes:           body.Notes,
		})
	}

	writeJSON(w, http.StatusCreated, rec)
}

// ListIntegrationRequests handles GET /api/v1/admin/integration-requests (platform-owner only).
func (h *IntegrationRequestHandler) ListIntegrationRequests(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	q := h.ent.IntegrationRequest.Query()
	if status := r.URL.Query().Get("status"); status != "" {
		q = q.Where(integrationrequest.StatusEQ(integrationrequest.Status(status)))
	}
	items, err := q.Order(ent.Desc(integrationrequest.FieldCreatedAt)).All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list requests", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// UpdateIntegrationRequestStatus handles PATCH /api/v1/admin/integration-requests/{id}
// (platform-owner only) — moves a request through pending -> in_review -> approved/rejected ->
// completed. Provisioning itself (creating the CustomAddon / flipping the tenant's feature or
// API-key environment) remains a separate MANUAL step by the platform admin, per the "manual v1"
// decision — this endpoint only tracks the review state and notes.
func (h *IntegrationRequestHandler) UpdateIntegrationRequestStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}
	var body struct {
		Status     string `json:"status"`
		AdminNotes string `json:"admin_notes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid body", nil)
		return
	}
	update := h.ent.IntegrationRequest.UpdateOneID(id).SetUpdatedAt(time.Now())
	if body.Status != "" {
		update = update.SetStatus(integrationrequest.Status(body.Status))
	}
	if body.AdminNotes != "" {
		update = update.SetAdminNotes(body.AdminNotes)
	}
	rec, err := update.Save(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "request not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update request", nil)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// s2sNotifyIntegrationRequestBody is what codevertex-website posts after saving its own Lead
// row -- this endpoint only triggers the notification, it never persists an IntegrationRequest
// (the website keeps owning its own Lead record; no duplicated data).
type s2sNotifyIntegrationRequestBody struct {
	RequestType     string `json:"request_type"`
	IntegrationMode string `json:"integration_mode"`
	CompanyName     string `json:"company_name"`
	RequesterName   string `json:"requester_name"`
	RequesterEmail  string `json:"requester_email"`
	RequesterPhone  string `json:"requester_phone"`
	Notes           string `json:"notes"`
}

// S2SNotifyIntegrationRequest handles POST /api/v1/s2s/notifications/etims-integration-request
// (INTERNAL_SERVICE_KEY gated at the router level, same as the other /s2s routes).
func (h *IntegrationRequestHandler) S2SNotifyIntegrationRequest(w http.ResponseWriter, r *http.Request) {
	var body s2sNotifyIntegrationRequestBody
	if err := decodeJSON(r, &body); err != nil || body.RequesterEmail == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "requester_email is required", nil)
		return
	}
	if body.RequestType == "" {
		body.RequestType = "etims_integration"
	}
	if h.notifier != nil {
		h.notifier.Notify(r.Context(), EtimsSupportNotification{
			RequestType:     body.RequestType,
			IntegrationMode: body.IntegrationMode,
			CompanyName:     body.CompanyName,
			RequesterName:   body.RequesterName,
			RequesterEmail:  body.RequesterEmail,
			RequesterPhone:  body.RequesterPhone,
			Source:          "public_website",
			Notes:           body.Notes,
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "notified"})
}
