package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/token"
	"go.uber.org/zap"
)

// isPlatformOrS2SAdmin reports whether claims belong to a platform owner (admin-tier role within
// the "codevertex" tenant) or an admin-scoped S2S token. A bare "admin" or "superuser" role string
// does not count, since TenantMembership roles are tenant-scoped, not global.
func isPlatformOrS2SAdmin(claims *token.Claims) bool {
	if claims.IsPlatformOwner {
		return true
	}
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// APIKeyHandler validates App secrets (the X-API-Key value) for other services. Every credential
// is an App; the retired api_keys table is gone.
type APIKeyHandler struct {
	ent         *ent.Client
	logger      *zap.Logger
	internalKey string // see SetInternalServiceKey
}

// NewAPIKeyHandler creates the validation handler.
func NewAPIKeyHandler(entClient *ent.Client, logger *zap.Logger) *APIKeyHandler {
	return &APIKeyHandler{ent: entClient, logger: logger}
}

// ValidateAPIKeyResponse is the caller identity behind a valid App secret.
type ValidateAPIKeyResponse struct {
	ClientID    string   `json:"client_id"`
	TenantID    string   `json:"tenant_id"`
	TenantSlug  string   `json:"tenant_slug"`
	Scopes      []string `json:"scopes"`
	Roles       []string `json:"roles"`
	Service     string   `json:"service,omitempty"`
	Environment string   `json:"environment"` // sandbox or production
}

// hashAPIKey is the SHA-256 hex digest stored for every App secret (256-bit random secrets need
// no salt).
func hashAPIKey(key string) string {
	hashBytes := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hashBytes[:])
}

// ValidateAPIKey validates the App secret in X-API-Key and returns the caller identity. Shared
// auth-client calls it from every service (GET /api/v1/admin/api-keys/validate).
func (h *APIKeyHandler) ValidateAPIKey(w http.ResponseWriter, r *http.Request) {
	tokenHeader := r.Header.Get("X-API-Key")
	if tokenHeader == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing X-API-Key header", nil)
		return
	}
	resp, statusCode, errCode, errMsg, err := h.ResolveAnyToken(r.Context(), r, tokenHeader)
	if err != nil {
		writeError(w, statusCode, errCode, errMsg, nil)
		return
	}
	writeJSON(w, http.StatusOK, *resp)
}

// ResolveAnyToken resolves an App secret in-process. Kept as the shared entry point for the
// validate endpoint and the Swagger docs handler.
func (h *APIKeyHandler) ResolveAnyToken(ctx context.Context, r *http.Request, tokenHeader string) (resp *ValidateAPIKeyResponse, statusCode int, errCode string, errMsg string, err error) {
	return h.ResolveAppToken(ctx, r, tokenHeader)
}

// ResolveAppToken looks an App up by its secret's hash, whatever the secret's prefix, and checks
// status, expiry and the IP allowlist.
func (h *APIKeyHandler) ResolveAppToken(ctx context.Context, r *http.Request, tokenHeader string) (resp *ValidateAPIKeyResponse, statusCode int, errCode string, errMsg string, err error) {
	a, lookupErr := h.ent.App.Query().
		Where(entapp.KeyHashEQ(hashAPIKey(tokenHeader)), entapp.StatusEQ(entapp.StatusActive)).
		Only(ctx)
	if lookupErr != nil {
		if ent.IsNotFound(lookupErr) {
			h.logger.Warn("invalid app secret", zap.String("prefix", getKeyPrefix(tokenHeader)))
			return nil, http.StatusUnauthorized, "unauthorized", "invalid token", lookupErr
		}
		h.logger.Error("app secret lookup", zap.Error(lookupErr))
		return nil, http.StatusInternalServerError, "server_error", "validation failed", lookupErr
	}

	if a.ExpiresAt != nil && !a.ExpiresAt.IsZero() && time.Now().After(*a.ExpiresAt) {
		return nil, http.StatusUnauthorized, "unauthorized", "token expired", fmt.Errorf("token expired")
	}
	if len(a.AllowedIps) > 0 && r != nil {
		if !ipAllowed(a.AllowedIps, h.allowlistIP(r)) {
			return nil, http.StatusForbidden, "forbidden", "IP not allowed", fmt.Errorf("ip not allowed")
		}
	}

	go func() {
		clientIP := ""
		if r != nil {
			clientIP = h.allowlistIP(r)
		}
		_, _ = h.ent.App.UpdateOneID(a.ID).SetLastUsedAt(time.Now()).SetLastUsedIP(clientIP).Save(context.Background())
	}()

	tenantSlug, tenantIDStr := "", ""
	if a.TenantID != nil {
		tenantIDStr = a.TenantID.String()
		if t, err := h.ent.Tenant.Query().Where(tenant.IDEQ(*a.TenantID)).Only(ctx); err == nil {
			tenantSlug = t.Slug
		}
	}

	roles := []string{"service"}
	if a.AppType == entapp.AppTypePlatform {
		roles = []string{"superuser", "service"}
	}

	return &ValidateAPIKeyResponse{
		ClientID:    a.ClientID,
		TenantID:    tenantIDStr,
		TenantSlug:  tenantSlug,
		Scopes:      a.Scopes,
		Roles:       roles,
		Service:     string(a.AppType),
		Environment: string(a.Environment),
	}, http.StatusOK, "", "", nil
}

// getKeyPrefix extracts the prefix from a secret for logging.
func getKeyPrefix(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

// getClientIP is the caller's address as the ingress established it. The IP allowlist is checked
// against it, so it never comes from X-Forwarded-For: a caller holding a leaked secret could
// otherwise name an allowed address in that header.
func getClientIP(r *http.Request) string {
	return clientIP(r)
}
