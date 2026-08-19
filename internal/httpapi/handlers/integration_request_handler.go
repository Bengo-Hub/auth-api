package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/ent/integrationrequest"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// developerDocsURL points a freshly-provisioned developer at the docs hub. Not read
// from config — this handler has no config dependency today, and the docs hub host
// doesn't vary per environment the way service base URLs do.
const developerDocsURL = "https://accounts.codevertexafrica.com/docs"

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

// ListMyIntegrationRequests handles GET /api/v1/integration-requests/mine (any authenticated
// user) — the caller's own requests, keyed by their JWT email. Used by the developer portal to
// check request status for a given resource (e.g. docs access, app production promotion)
// without needing admin scope just to see your own submissions.
func (h *IntegrationRequestHandler) ListMyIntegrationRequests(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims.Email == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	items, err := h.ent.IntegrationRequest.Query().
		Where(integrationrequest.RequesterEmailEQ(claims.Email)).
		Order(ent.Desc(integrationrequest.FieldCreatedAt)).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list requests", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
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
// completed. Provisioning a genuinely NEW tenant (an external developer with no account yet:
// docs access or an eTIMS integration lead) is now automatic on approval — see
// autoProvisionExternalDeveloper. Any other integration (a request tied to an EXISTING tenant,
// or a request_type not on the auto-provision list) is still a manual step by the platform
// admin, per the original "manual v1" decision — auto-provisioning only ever creates a tenant
// that didn't exist before; it never touches an existing one.
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

	if rec.Status == integrationrequest.StatusApproved && rec.TenantID == nil {
		go h.autoProvisionExternalDeveloper(context.WithoutCancel(r.Context()), rec)
	}

	writeJSON(w, http.StatusOK, rec)
}

// autoProvisionRequestTypes: request types where "no tenant yet" genuinely means a brand-new
// external developer who should get one auto-created, not an existing tenant's own request that
// simply forgot to attach its tenant_id. app_production_access is deliberately excluded — an App
// requires a tenant to exist already (see AppHandler.CreateApp), so that request type can never
// legitimately have a nil TenantID in the first place.
var autoProvisionRequestTypes = map[string]bool{
	"etims_integration": true,
}

func isAutoProvisionable(requestType string) bool {
	return autoProvisionRequestTypes[requestType] || strings.HasPrefix(requestType, "docs_access_")
}

// autoProvisionExternalDeveloper creates a lightweight tenant + sandbox App for a newly
// approved, no-tenant-yet developer request, links every one of that requester's past/future
// requests to it (idempotent — a second approved request from the same email reuses the tenant
// rather than creating another one), and emails the requester their sandbox key. Runs async and
// best-effort: called after the status update has already been saved and returned to the caller,
// so a failure here never blocks or undoes the approval itself — it just leaves TenantID nil for
// a human to finish manually, exactly like before this existed.
func (h *IntegrationRequestHandler) autoProvisionExternalDeveloper(ctx context.Context, rec *ent.IntegrationRequest) {
	if !isAutoProvisionable(rec.RequestType) {
		return
	}

	log := h.logger.With(zap.String("request_id", rec.ID.String()), zap.String("requester_email", rec.RequesterEmail))

	// Idempotency: has this exact requester already been auto-provisioned via an earlier
	// approved request? Reuse that tenant instead of creating a second one.
	if existing, err := h.ent.IntegrationRequest.Query().
		Where(
			integrationrequest.RequesterEmailEQ(rec.RequesterEmail),
			integrationrequest.TenantIDNotNil(),
			integrationrequest.IDNEQ(rec.ID),
		).
		Order(ent.Desc(integrationrequest.FieldCreatedAt)).
		First(ctx); err == nil && existing.TenantID != nil {
		if _, err := h.ent.IntegrationRequest.UpdateOneID(rec.ID).SetTenantID(*existing.TenantID).Save(ctx); err != nil {
			log.Warn("auto-provision: link to existing tenant failed", zap.Error(err))
		}
		return
	}

	name := rec.CompanyName
	if name == "" {
		name = rec.RequesterName
	}
	slug := developerTenantSlug(name, rec.ID)

	tenantRec, err := h.ent.Tenant.Create().
		SetName(name).
		SetSlug(slug).
		SetUseCase("developer_external").
		SetStatus("active").
		SetContactEmail(rec.RequesterEmail).
		SetContactPhone(rec.RequesterPhone).
		Save(ctx)
	if err != nil {
		log.Error("auto-provision: create tenant failed", zap.Error(err))
		return
	}

	token, prefix, hash, err := generateAppToken()
	if err != nil {
		log.Error("auto-provision: generate app token failed", zap.Error(err))
		return
	}
	clientID, err := generateClientID()
	if err != nil {
		log.Error("auto-provision: generate client id failed", zap.Error(err))
		return
	}
	if _, err := h.ent.App.Create().
		SetName(name + " — Sandbox").
		SetDescription("Auto-provisioned on integration-request approval (" + rec.RequestType + ")").
		SetAppType(entapp.AppTypeTenant).
		SetEnvironment(entapp.EnvironmentSandbox).
		SetClientID(clientID).
		SetKeyHash(hash).
		SetKeyPrefix(prefix).
		SetTenantID(tenantRec.ID).
		SetStatus(entapp.StatusActive).
		Save(ctx); err != nil {
		log.Error("auto-provision: create sandbox app failed", zap.Error(err))
		return
	}

	if _, err := h.ent.IntegrationRequest.UpdateOneID(rec.ID).SetTenantID(tenantRec.ID).Save(ctx); err != nil {
		log.Warn("auto-provision: linking request to new tenant failed", zap.Error(err))
	}

	if h.notifier != nil {
		h.notifier.NotifyDeveloperProvisioned(ctx, DeveloperProvisioned{
			RequesterName:  rec.RequesterName,
			RequesterEmail: rec.RequesterEmail,
			TenantSlug:     tenantRec.Slug,
			SandboxKey:     token,
			DocsURL:        developerDocsURL,
		})
	}

	log.Info("auto-provisioned external developer", zap.String("tenant_slug", tenantRec.Slug))
}

// developerTenantSlug derives a URL-safe, reasonably unique slug from a company/requester
// name plus a short suffix from the request ID — collisions are astronomically unlikely (the
// suffix alone is 8 hex chars of a UUID) without needing a DB round-trip to check uniqueness
// before insert; Tenant.slug is still uniquely indexed, so a genuine collision fails loudly at
// Create() rather than silently overwriting another tenant.
func developerTenantSlug(name string, requestID uuid.UUID) string {
	base := strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	lastDash := false
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteRune('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "developer"
	}
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	return slug + "-" + strings.ReplaceAll(requestID.String(), "-", "")[:8]
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
