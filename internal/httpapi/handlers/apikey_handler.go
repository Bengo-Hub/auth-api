package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/apikey"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// APIKeyHandler handles API key management and validation.
type APIKeyHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

// NewAPIKeyHandler creates a new API key handler.
func NewAPIKeyHandler(entClient *ent.Client, logger *zap.Logger) *APIKeyHandler {
	return &APIKeyHandler{
		ent:    entClient,
		logger: logger,
	}
}

// CreateAPIKeyRequest represents a request to create an API key.
type CreateAPIKeyRequest struct {
	Name       string   `json:"name"`
	Service    string   `json:"service,omitempty"`    // Service name for service accounts
	Scopes     []string `json:"scopes,omitempty"`     // Allowed scopes
	AllowedIPs []string `json:"allowed_ips,omitempty"` // IP whitelist
	ExpiresIn  int      `json:"expires_in,omitempty"` // Expiration in days (0 = never)
}

// CreateAPIKeyResponse returns the created API key (only shown once).
type CreateAPIKeyResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`       // Plain text key - only returned on creation
	KeyPrefix string    `json:"key_prefix"` // Prefix for identification
	Service   string    `json:"service,omitempty"`
	Scopes    []string  `json:"scopes,omitempty"`
	ExpiresAt *string   `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidateAPIKeyResponse returns information about a valid API key.
type ValidateAPIKeyResponse struct {
	ClientID   string   `json:"client_id"` // API key ID
	TenantID   string   `json:"tenant_id"`
	TenantSlug string   `json:"tenant_slug"`
	Scopes     []string `json:"scopes"`
	Roles      []string `json:"roles"`
	Service    string   `json:"service,omitempty"`
}

// generateAPIKey generates a cryptographically secure API key.
func generateAPIKey() (key string, prefix string, hash string, err error) {
	// Generate 32 bytes of random data
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", err
	}

	// Create the key with prefix for identification
	key = "bng_" + base64.URLEncoding.EncodeToString(b)
	prefix = key[:8]

	// Hash the key for storage
	hashBytes := sha256.Sum256([]byte(key))
	hash = hex.EncodeToString(hashBytes[:])

	return key, prefix, hash, nil
}

// hashAPIKey hashes an API key for lookup.
func hashAPIKey(key string) string {
	hashBytes := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hashBytes[:])
}

// CreateAPIKey creates a new API key.
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	// Require admin scope for API key creation
	isAdmin := false
	for _, role := range claims.Roles {
		if role == "superuser" || role == "admin" {
			isAdmin = true
			break
		}
	}
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	var req CreateAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required", nil)
		return
	}

	// Generate the API key
	key, prefix, keyHash, err := generateAPIKey()
	if err != nil {
		h.logger.Error("failed to generate API key", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate key", nil)
		return
	}

	// Parse tenant ID from claims
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id in token", nil)
		return
	}

	// Parse user ID for created_by
	userID, _ := uuid.Parse(claims.Subject)

	// Build the API key record
	create := h.ent.APIKey.Create().
		SetName(req.Name).
		SetKeyHash(keyHash).
		SetKeyPrefix(prefix).
		SetTenantID(tenantID).
		SetCreatedBy(userID).
		SetStatus(apikey.StatusActive)

	if req.Service != "" {
		create.SetService(req.Service)
	}
	if len(req.Scopes) > 0 {
		create.SetScopes(req.Scopes)
	}
	if len(req.AllowedIPs) > 0 {
		create.SetAllowedIps(req.AllowedIPs)
	}
	if req.ExpiresIn > 0 {
		expiresAt := time.Now().AddDate(0, 0, req.ExpiresIn)
		create.SetExpiresAt(expiresAt)
	}

	apiKey, err := create.Save(r.Context())
	if err != nil {
		h.logger.Error("failed to save API key", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create API key", nil)
		return
	}

	// Log the creation
	h.logger.Info("API key created",
		zap.String("key_id", apiKey.ID.String()),
		zap.String("name", req.Name),
		zap.String("tenant_id", tenantID.String()),
		zap.String("created_by", userID.String()),
	)

	// Build response with plain text key (only shown once)
	resp := CreateAPIKeyResponse{
		ID:        apiKey.ID.String(),
		Name:      apiKey.Name,
		Key:       key, // Plain text - only returned on creation
		KeyPrefix: prefix,
		Service:   apiKey.Service,
		Scopes:    apiKey.Scopes,
		CreatedAt: apiKey.CreatedAt,
	}
	if apiKey.ExpiresAt != nil && !apiKey.ExpiresAt.IsZero() {
		exp := apiKey.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &exp
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ValidateAPIKey validates an API key and returns its metadata.
// This endpoint is called by other services to validate API keys.
// It accepts the API key in the X-API-Key header.
func (h *APIKeyHandler) ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	apiKeyHeader := r.Header.Get("X-API-Key")
	if apiKeyHeader == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing X-API-Key header", nil)
		return
	}

	// Hash the provided key for lookup
	keyHash := hashAPIKey(apiKeyHeader)

	// Look up the API key
	key, err := h.ent.APIKey.Query().
		Where(
			apikey.KeyHashEQ(keyHash),
			apikey.StatusEQ(apikey.StatusActive),
		).
		Only(r.Context())

	if err != nil {
		if ent.IsNotFound(err) {
			h.logger.Warn("invalid API key attempted",
				zap.String("key_prefix", getKeyPrefix(apiKeyHeader)),
			)
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid API key", nil)
			return
		}
		h.logger.Error("failed to lookup API key", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "validation failed", nil)
		return
	}

	// Check expiration
	if key.ExpiresAt != nil && !key.ExpiresAt.IsZero() && time.Now().After(*key.ExpiresAt) {
		h.logger.Warn("expired API key used",
			zap.String("key_id", key.ID.String()),
		)
		writeError(w, http.StatusUnauthorized, "unauthorized", "API key expired", nil)
		return
	}

	// Check IP whitelist if configured
	if len(key.AllowedIps) > 0 {
		clientIP := getClientIP(r)
		allowed := false
		for _, ip := range key.AllowedIps {
			if ip == clientIP || ip == "*" {
				allowed = true
				break
			}
		}
		if !allowed {
			h.logger.Warn("API key used from unauthorized IP",
				zap.String("key_id", key.ID.String()),
				zap.String("client_ip", clientIP),
			)
			writeError(w, http.StatusForbidden, "forbidden", "IP not allowed", nil)
			return
		}
	}

	// Update last used timestamp (async to not block response)
	go func() {
		clientIP := getClientIP(r)
		_, _ = h.ent.APIKey.UpdateOneID(key.ID).
			SetLastUsedAt(time.Now()).
			SetLastUsedIP(clientIP).
			Save(r.Context())
	}()

	// Look up tenant slug for platform owner detection
	tenantSlug := ""
	if tenantEntity, err := h.ent.Tenant.Query().
		Where(tenant.IDEQ(key.TenantID)).
		Only(r.Context()); err == nil {
		tenantSlug = tenantEntity.Slug
	}

	// Determine roles: service keys get superuser access, regular keys use stored scopes
	roles := []string{}
	if key.Service != "" {
		roles = []string{"superuser"}
	}

	// Return validation response
	writeJSON(w, http.StatusOK, ValidateAPIKeyResponse{
		ClientID:   key.ID.String(),
		TenantID:   key.TenantID.String(),
		TenantSlug: tenantSlug,
		Scopes:     key.Scopes,
		Roles:      roles,
		Service:    key.Service,
	})
}

// ListAPIKeys lists all API keys for the current tenant.
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}

	keys, err := h.ent.APIKey.Query().
		Where(apikey.TenantIDEQ(tenantID)).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to list API keys", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list keys", nil)
		return
	}

	// Return sanitized list (no key hashes)
	type keyInfo struct {
		ID         string    `json:"id"`
		Name       string    `json:"name"`
		KeyPrefix  string    `json:"key_prefix"`
		Service    string    `json:"service,omitempty"`
		Scopes     []string  `json:"scopes,omitempty"`
		Status     string    `json:"status"`
		LastUsedAt *string   `json:"last_used_at,omitempty"`
		ExpiresAt  *string   `json:"expires_at,omitempty"`
		CreatedAt  time.Time `json:"created_at"`
	}

	var result []keyInfo
	for _, k := range keys {
		info := keyInfo{
			ID:        k.ID.String(),
			Name:      k.Name,
			KeyPrefix: k.KeyPrefix,
			Service:   k.Service,
			Scopes:    k.Scopes,
			Status:    string(k.Status),
			CreatedAt: k.CreatedAt,
		}
		if k.LastUsedAt != nil && !k.LastUsedAt.IsZero() {
			t := k.LastUsedAt.Format(time.RFC3339)
			info.LastUsedAt = &t
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.IsZero() {
			t := k.ExpiresAt.Format(time.RFC3339)
			info.ExpiresAt = &t
		}
		result = append(result, info)
	}

	writeJSON(w, http.StatusOK, result)
}

// RevokeAPIKey revokes an API key.
func (h *APIKeyHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	keyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid key ID", nil)
		return
	}

	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}

	// Get the key and verify ownership
	key, err := h.ent.APIKey.Query().
		Where(
			apikey.IDEQ(keyID),
			apikey.TenantIDEQ(tenantID),
		).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "API key not found", nil)
			return
		}
		h.logger.Error("failed to get API key", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get key", nil)
		return
	}

	// Parse reason from body
	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)

	// Revoke the key
	now := time.Now()
	_, err = h.ent.APIKey.UpdateOneID(key.ID).
		SetStatus(apikey.StatusRevoked).
		SetRevokedAt(now).
		SetRevokedReason(req.Reason).
		Save(r.Context())
	if err != nil {
		h.logger.Error("failed to revoke API key", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to revoke key", nil)
		return
	}

	h.logger.Info("API key revoked",
		zap.String("key_id", keyID.String()),
		zap.String("revoked_by", claims.Subject),
		zap.String("reason", req.Reason),
	)

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// getKeyPrefix extracts the prefix from an API key for logging.
func getKeyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxied requests)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}
