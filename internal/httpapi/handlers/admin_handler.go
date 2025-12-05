package handlers

import (
	"net/http"

	"github.com/bengobox/auth-service/internal/ent"
	"github.com/bengobox/auth-service/internal/ent/oauthclient"
	"github.com/bengobox/auth-service/internal/ent/tenant"
	authmiddleware "github.com/bengobox/auth-service/internal/httpapi/middleware"
	"github.com/bengobox/auth-service/internal/services/entitlements"
	"github.com/bengobox/auth-service/internal/services/usage"
	"github.com/bengobox/auth-service/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminHandler provides basic tenant/client admin APIs.
type AdminHandler struct {
	ent    *ent.Client
	logger *zap.Logger
	entSvc *entitlements.Service
	useSvc *usage.Service
	tokens *token.Service
}

func NewAdminHandler(entClient *ent.Client, tokens *token.Service, logger *zap.Logger) *AdminHandler {
	return &AdminHandler{
		ent:    entClient,
		logger: logger,
		entSvc: entitlements.New(entClient),
		useSvc: usage.New(entClient),
		tokens: tokens,
	}
}

func (h *AdminHandler) requireAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}

	// Superuser bypass: check if user has superuser role (bypasses all RBAC/permissions)
	// Superuser role is set in TenantMembership and included in token claims
	for _, role := range claims.Roles {
		if role == "superuser" {
			return true
		}
	}

	// Check for admin scopes
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// Tenants
type tenantRequest struct {
	ID           string                 `json:"id,omitempty"` // Tenant UUID - must match across all services
	Name         string                 `json:"name"`
	Slug         string                 `json:"slug"`
	ContactEmail string                 `json:"contact_email,omitempty"`
	ContactPhone string                 `json:"contact_phone,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

func (h *AdminHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req tenantRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" || req.Slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	create := h.ent.Tenant.Create().
		SetName(req.Name).
		SetSlug(req.Slug).
		SetStatus("active")

	// If tenant ID is provided, use it (for cross-service tenant sync)
	if req.ID != "" {
		tenantID, err := uuid.Parse(req.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant ID format", nil)
			return
		}
		create.SetID(tenantID)
	}

	// Set optional fields (contact info stored in metadata since schema doesn't have those fields)
	metadata := make(map[string]interface{})
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	if req.ContactEmail != "" {
		metadata["contact_email"] = req.ContactEmail
	}
	if req.ContactPhone != "" {
		metadata["contact_phone"] = req.ContactPhone
	}
	if len(metadata) > 0 {
		create.SetMetadata(metadata)
	}

	t, err := create.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "conflict", "could not create tenant", nil)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

// CreateTenantPublic creates a tenant via public endpoint (for tenant auto-discovery).
// This endpoint does not require authentication and is used by services to sync tenants.
func (h *AdminHandler) CreateTenantPublic(w http.ResponseWriter, r *http.Request) {
	var req tenantRequest
	if err := decodeJSON(r, &req); err != nil || req.Slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload: slug is required", nil)
		return
	}

	// Name is required, use slug as fallback
	if req.Name == "" {
		req.Name = req.Slug
	}

	create := h.ent.Tenant.Create().
		SetName(req.Name).
		SetSlug(req.Slug).
		SetStatus("active")

	// If tenant ID is provided, use it (for cross-service tenant sync with matching UUIDs)
	if req.ID != "" {
		tenantID, err := uuid.Parse(req.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant ID format", nil)
			return
		}
		create.SetID(tenantID)
	}

	// Set optional fields (contact info stored in metadata since schema doesn't have those fields)
	metadata := make(map[string]interface{})
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	if req.ContactEmail != "" {
		metadata["contact_email"] = req.ContactEmail
	}
	if req.ContactPhone != "" {
		metadata["contact_phone"] = req.ContactPhone
	}
	if len(metadata) > 0 {
		create.SetMetadata(metadata)
	}

	t, err := create.Save(r.Context())
	if err != nil {
		// Check if tenant already exists (idempotent)
		existing, err := h.ent.Tenant.Query().
			Where(tenant.SlugEQ(req.Slug)).
			Only(r.Context())
		if err == nil && existing != nil {
			writeJSON(w, http.StatusOK, existing)
			return
		}
		writeError(w, http.StatusBadRequest, "conflict", "could not create tenant", nil)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

// GetTenantBySlugPublic retrieves a tenant by slug via public endpoint (for tenant auto-discovery).
func (h *AdminHandler) GetTenantBySlugPublic(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "slug is required", nil)
		return
	}

	t, err := h.ent.Tenant.Query().
		Where(tenant.SlugEQ(slug)).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get tenant", nil)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	items, err := h.ent.Tenant.Query().Where(tenant.StatusEQ("active")).All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list tenants", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// Clients
type clientRequest struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Public       bool     `json:"public"`
	TenantID     string   `json:"tenant_id"`
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req clientRequest
	if err := decodeJSON(r, &req); err != nil || req.ClientID == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	create := h.ent.OAuthClient.Create().
		SetClientID(req.ClientID).
		SetName(req.Name).
		SetRedirectUris(req.RedirectURIs).
		SetAllowedScopes(req.Scopes).
		SetPublic(req.Public)
	if req.TenantID != "" {
		create.SetTenantID(req.TenantID)
	}
	c, err := create.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "conflict", "could not create client", nil)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	items, err := h.ent.OAuthClient.Query().Where(oauthclient.PublicEQ(true)).All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list clients", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// Key rotation
func (h *AdminHandler) RotateKeys(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	if h.tokens == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "token service not available", nil)
		return
	}
	if err := h.tokens.ReloadFromFiles(); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "reload failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated"})
}

// Entitlements endpoints
type entitlementUpsertRequest struct {
	TenantID    string         `json:"tenant_id"`
	FeatureCode string         `json:"feature_code"`
	Limit       map[string]any `json:"limit"`
	PlanSource  string         `json:"plan_source"`
}

func (h *AdminHandler) UpsertEntitlement(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req entitlementUpsertRequest
	if err := decodeJSON(r, &req); err != nil || req.TenantID == "" || req.FeatureCode == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	tenantID, _ := uuid.Parse(req.TenantID)
	if err := h.entSvc.Upsert(r.Context(), entitlements.Entitlement{
		TenantID:    tenantID,
		FeatureCode: req.FeatureCode,
		Limit:       req.Limit,
		PlanSource:  req.PlanSource,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "upsert failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AdminHandler) ListEntitlements(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	tenantIDStr := r.URL.Query().Get("tenant_id")
	tenantID, _ := uuid.Parse(tenantIDStr)
	items, err := h.entSvc.List(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "list failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// Usage endpoint (increment)
type usageIncRequest struct {
	TenantID string `json:"tenant_id"`
	Type     string `json:"type"`
	Amount   int    `json:"amount"`
}

func (h *AdminHandler) IncrementUsage(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req usageIncRequest
	if err := decodeJSON(r, &req); err != nil || req.TenantID == "" || req.Type == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	tenantID, _ := uuid.Parse(req.TenantID)
	var err error
	switch req.Type {
	case "auth_transactions":
		err = h.useSvc.IncrementAuthTransactions(r.Context(), tenantID, req.Amount)
	case "mfa_prompts":
		err = h.useSvc.IncrementMFAPrompts(r.Context(), tenantID, req.Amount)
	default:
		writeError(w, http.StatusBadRequest, "invalid_type", "unsupported usage type", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "increment failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
