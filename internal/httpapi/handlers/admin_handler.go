package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/bengobox/auth-service/internal/ent"
	"github.com/bengobox/auth-service/internal/ent/oauthclient"
	"github.com/bengobox/auth-service/internal/ent/tenant"
	authmiddleware "github.com/bengobox/auth-service/internal/httpapi/middleware"
	"github.com/bengobox/auth-service/internal/services/entitlements"
	"github.com/bengobox/auth-service/internal/services/usage"
	"github.com/bengobox/auth-service/internal/token"
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
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// Tenants
type tenantRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
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
	t, err := h.ent.Tenant.Create().
		SetName(req.Name).
		SetSlug(req.Slug).
		SetStatus("active").
		Save(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "conflict", "could not create tenant", nil)
		return
	}
	writeJSON(w, http.StatusCreated, t)
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

// API Keys
type apiKeyRequest struct {
	Name     string   `json:"name"`
	Service  string   `json:"service"` // e.g., "notifications-app", "logistics-service"
	TenantID string   `json:"tenant_id"`
	Scopes   []string `json:"scopes"`
}

type apiKeyResponse struct {
	ClientID  string   `json:"client_id"`
	APIKey    string   `json:"api_key"` // Only shown once on creation
	Name      string   `json:"name"`
	Service   string   `json:"service"`
	TenantID  string   `json:"tenant_id"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"created_at"`
}

func (h *AdminHandler) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req apiKeyRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" || req.Service == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name and service are required", nil)
		return
	}

	// Generate a secure API key (32 bytes = 64 hex characters)
	apiKeyBytes := make([]byte, 32)
	if _, err := rand.Read(apiKeyBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate API key", nil)
		return
	}
	apiKey := fmt.Sprintf("bengobox_%s", hex.EncodeToString(apiKeyBytes))

	// Generate client_id from service name
	clientID := fmt.Sprintf("api-key-%s-%s", req.Service, uuid.New().String()[:8])

	// Store API key as client_secret in OAuthClient
	create := h.ent.OAuthClient.Create().
		SetClientID(clientID).
		SetClientSecret(apiKey). // Store plain API key
		SetName(req.Name).
		SetAllowedScopes(req.Scopes).
		SetPublic(false) // API keys are not public clients
	if req.TenantID != "" {
		create.SetTenantID(req.TenantID)
	}
	// Store service name in metadata
	create.SetMetadata(map[string]any{
		"type":    "api_key",
		"service": req.Service,
	})

	c, err := create.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "conflict", "could not create API key", nil)
		return
	}

	writeJSON(w, http.StatusCreated, apiKeyResponse{
		ClientID:  c.ClientID,
		APIKey:    apiKey, // Return plain API key only once
		Name:      c.Name,
		Service:   req.Service,
		TenantID:  c.TenantID,
		Scopes:    c.AllowedScopes,
		CreatedAt: c.CreatedAt.Format(time.RFC3339),
	})
}

func (h *AdminHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	serviceFilter := r.URL.Query().Get("service")
	query := h.ent.OAuthClient.Query()
	items, err := query.All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list API keys", nil)
		return
	}
	// Filter by metadata type = "api_key"
	var filtered []*ent.OAuthClient
	for _, item := range items {
		if item.Metadata != nil {
			if metaType, ok := item.Metadata["type"].(string); ok && metaType == "api_key" {
				if serviceFilter == "" || item.Metadata["service"] == serviceFilter {
					// ClientSecret is already excluded from JSON serialization (json:"-")
					filtered = append(filtered, item)
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (h *AdminHandler) ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing API key", nil)
		return
	}

	// Find OAuthClient by client_secret (API key)
	items, err := h.ent.OAuthClient.Query().All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to validate API key", nil)
		return
	}

	for _, item := range items {
		if item.ClientSecret == apiKey {
			// Check if it's an API key (not a regular OAuth client)
			if item.Metadata != nil {
				if metaType, ok := item.Metadata["type"].(string); ok && metaType == "api_key" {
					service, _ := item.Metadata["service"].(string)
					writeJSON(w, http.StatusOK, map[string]any{
						"client_id": item.ClientID,
						"tenant_id": item.TenantID,
						"scopes":    item.AllowedScopes,
						"service":   service,
					})
					return
				}
			}
		}
	}

	writeError(w, http.StatusUnauthorized, "unauthorized", "invalid API key", nil)
}
