package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/app"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AppHandler handles platform/tenant app management and S2S token validation.
type AppHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

// NewAppHandler creates a new AppHandler.
func NewAppHandler(entClient *ent.Client, logger *zap.Logger) *AppHandler {
	return &AppHandler{ent: entClient, logger: logger}
}

// ── Request / Response types ─────────────────────────────────────────────────

type CreateAppRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	AppType     string   `json:"app_type"` // "platform" | "tenant"
	Scopes      []string `json:"scopes,omitempty"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	ExpiresIn   int      `json:"expires_in,omitempty"` // days; 0 = never
}

type AppResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	AppType     string    `json:"app_type"`
	ClientID    string    `json:"client_id"`
	KeyPrefix   string    `json:"key_prefix"`
	TenantID    *string   `json:"tenant_id,omitempty"`
	Scopes      []string  `json:"scopes,omitempty"`
	AllowedIPs  []string  `json:"allowed_ips,omitempty"`
	Status      string    `json:"status"`
	ExpiresAt   *string   `json:"expires_at,omitempty"`
	LastUsedAt  *string   `json:"last_used_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateAppResponse struct {
	AppResponse
	Token string `json:"token"` // Full token — shown ONCE on creation
}

// ── Token generation helpers ─────────────────────────────────────────────────

// generateAppToken creates a GitHub-style app token: bng_app_<base64url(32 bytes)>
// Returns: fullToken, prefix (first 16 chars), sha256Hash
func generateAppToken() (token, prefix, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate random bytes: %w", err)
	}
	token = "bng_app_" + base64.URLEncoding.EncodeToString(b)
	if len(token) >= 16 {
		prefix = token[:16]
	} else {
		prefix = token
	}
	// Reuse hashAPIKey from apikey_handler.go (same package)
	hash = hashAPIKey(token)
	return token, prefix, hash, nil
}

// generateClientID creates a short public app identifier, e.g. "app_a1b2c3d4e5f6".
func generateClientID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "app_" + hex.EncodeToString(b), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// requirePlatformAdmin gates platform-type Apps management. A bare
// "superuser" role string must NOT qualify on its own: TenantMembership roles
// are tenant-scoped, so a "superuser" in any ordinary tenant would otherwise
// get platform-wide App management. Only claims.IsPlatformOwner (admin-tier
// role within the "codevertex" tenant specifically) counts.
func requirePlatformAdmin(claims *token.Claims) bool {
	return claims.IsPlatformOwner
}

func appToResponse(a *ent.App) AppResponse {
	resp := AppResponse{
		ID:          a.ID.String(),
		Name:        a.Name,
		Description: a.Description,
		AppType:     string(a.AppType),
		ClientID:    a.ClientID,
		KeyPrefix:   a.KeyPrefix,
		Scopes:      a.Scopes,
		AllowedIPs:  a.AllowedIps,
		Status:      string(a.Status),
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
	if a.TenantID != nil {
		s := a.TenantID.String()
		resp.TenantID = &s
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.IsZero() {
		s := a.ExpiresAt.Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	if a.LastUsedAt != nil && !a.LastUsedAt.IsZero() {
		s := a.LastUsedAt.Format(time.RFC3339)
		resp.LastUsedAt = &s
	}
	return resp
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// CreateApp creates a new platform or tenant app with a generated token.
func (h *AppHandler) CreateApp(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	var req CreateAppRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required", nil)
		return
	}

	// Platform apps require superuser; tenant apps require admin+.
	appType := app.AppType(req.AppType)
	if appType != app.AppTypePlatform && appType != app.AppTypeTenant {
		appType = app.AppTypeTenant
	}
	if appType == app.AppTypePlatform && !requirePlatformAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "superuser required for platform apps", nil)
		return
	}

	token, prefix, hash, err := generateAppToken()
	if err != nil {
		h.logger.Error("generate app token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "token generation failed", nil)
		return
	}
	clientID, err := generateClientID()
	if err != nil {
		h.logger.Error("generate client id", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "token generation failed", nil)
		return
	}

	createdBy, _ := uuid.Parse(claims.Subject)

	create := h.ent.App.Create().
		SetName(req.Name).
		SetDescription(req.Description).
		SetAppType(appType).
		SetClientID(clientID).
		SetKeyHash(hash).
		SetKeyPrefix(prefix).
		SetCreatedBy(createdBy).
		SetStatus(app.StatusActive)

	if appType == app.AppTypeTenant {
		if tenantID, err := uuid.Parse(claims.TenantID); err == nil {
			create.SetTenantID(tenantID)
		}
	}
	if len(req.Scopes) > 0 {
		create.SetScopes(req.Scopes)
	}
	if len(req.AllowedIPs) > 0 {
		create.SetAllowedIps(req.AllowedIPs)
	}
	if req.ExpiresIn > 0 {
		create.SetExpiresAt(time.Now().AddDate(0, 0, req.ExpiresIn))
	}

	created, err := create.Save(r.Context())
	if err != nil {
		h.logger.Error("save app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create app", nil)
		return
	}

	h.logger.Info("app created",
		zap.String("app_id", created.ID.String()),
		zap.String("name", req.Name),
		zap.String("type", string(appType)),
		zap.String("created_by", createdBy.String()),
	)

	writeJSON(w, http.StatusCreated, CreateAppResponse{
		AppResponse: appToResponse(created),
		Token:       token,
	})
}

// ListApps lists apps. Platform admins see all; tenant admins see their tenant's apps.
func (h *AppHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	q := h.ent.App.Query()
	if !requirePlatformAdmin(claims) {
		// Tenant admins only see their own apps.
		tenantID, err := uuid.Parse(claims.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
			return
		}
		q = q.Where(app.TenantIDEQ(tenantID))
	}

	apps, err := q.Order(ent.Desc(app.FieldCreatedAt)).All(r.Context())
	if err != nil {
		h.logger.Error("list apps", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list apps", nil)
		return
	}

	resp := make([]AppResponse, len(apps))
	for i, a := range apps {
		resp[i] = appToResponse(a)
	}
	writeJSON(w, http.StatusOK, resp)
}

// GetApp retrieves a single app by ID.
func (h *AppHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	appID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app id", nil)
		return
	}

	a, err := h.ent.App.Get(r.Context(), appID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "app not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get app", nil)
		return
	}

	// Verify access
	if !requirePlatformAdmin(claims) && (a.TenantID == nil || a.TenantID.String() != claims.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
		return
	}

	writeJSON(w, http.StatusOK, appToResponse(a))
}

// UpdateApp updates app metadata (name, description, scopes, allowed_ips).
func (h *AppHandler) UpdateApp(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	appID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app id", nil)
		return
	}

	existing, err := h.ent.App.Get(r.Context(), appID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "app not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get app", nil)
		return
	}
	if !requirePlatformAdmin(claims) && (existing.TenantID == nil || existing.TenantID.String() != claims.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Scopes      []string `json:"scopes"`
		AllowedIPs  []string `json:"allowed_ips"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid body", nil)
		return
	}

	update := h.ent.App.UpdateOneID(appID)
	if req.Name != "" {
		update.SetName(req.Name)
	}
	if req.Description != "" {
		update.SetDescription(req.Description)
	}
	if req.Scopes != nil {
		update.SetScopes(req.Scopes)
	}
	if req.AllowedIPs != nil {
		update.SetAllowedIps(req.AllowedIPs)
	}

	updated, err := update.Save(r.Context())
	if err != nil {
		h.logger.Error("update app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update app", nil)
		return
	}
	writeJSON(w, http.StatusOK, appToResponse(updated))
}

// RotateToken generates a new token for an app, invalidating the old one.
// Returns the new full token — shown once.
func (h *AppHandler) RotateToken(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	appID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app id", nil)
		return
	}

	existing, err := h.ent.App.Get(r.Context(), appID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "app not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get app", nil)
		return
	}
	if !requirePlatformAdmin(claims) && (existing.TenantID == nil || existing.TenantID.String() != claims.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
		return
	}

	newToken, newPrefix, newHash, err := generateAppToken()
	if err != nil {
		h.logger.Error("rotate app token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "token generation failed", nil)
		return
	}

	updated, err := h.ent.App.UpdateOneID(appID).
		SetKeyHash(newHash).
		SetKeyPrefix(newPrefix).
		SetStatus(app.StatusActive).
		Save(r.Context())
	if err != nil {
		h.logger.Error("save rotated app token", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to rotate token", nil)
		return
	}

	h.logger.Info("app token rotated",
		zap.String("app_id", appID.String()),
		zap.String("rotated_by", claims.Subject),
	)

	writeJSON(w, http.StatusOK, CreateAppResponse{
		AppResponse: appToResponse(updated),
		Token:       newToken,
	})
}

// RevokeApp marks an app as revoked, permanently disabling its token.
func (h *AppHandler) RevokeApp(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	appID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app id", nil)
		return
	}

	existing, err := h.ent.App.Get(r.Context(), appID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "app not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get app", nil)
		return
	}
	if !requirePlatformAdmin(claims) && (existing.TenantID == nil || existing.TenantID.String() != claims.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	_ = decodeJSON(r, &req)

	now := time.Now()
	_, err = h.ent.App.UpdateOneID(appID).
		SetStatus(app.StatusRevoked).
		SetRevokedAt(now).
		SetRevokedReason(req.Reason).
		Save(r.Context())
	if err != nil {
		h.logger.Error("revoke app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to revoke app", nil)
		return
	}

	h.logger.Info("app revoked",
		zap.String("app_id", appID.String()),
		zap.String("revoked_by", claims.Subject),
	)

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// DeleteApp hard-deletes an app. Only superusers may delete platform apps.
func (h *AppHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	appID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid app id", nil)
		return
	}

	existing, err := h.ent.App.Get(r.Context(), appID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "app not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get app", nil)
		return
	}
	if existing.AppType == app.AppTypePlatform && !requirePlatformAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "superuser required to delete platform apps", nil)
		return
	}
	if existing.AppType == app.AppTypeTenant && !requirePlatformAdmin(claims) &&
		(existing.TenantID == nil || existing.TenantID.String() != claims.TenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
		return
	}

	if err := h.ent.App.DeleteOneID(appID).Exec(r.Context()); err != nil {
		h.logger.Error("delete app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete app", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidateAppToken is intentionally absent: validation of bng_app_* tokens
// is handled by APIKeyHandler.ValidateAPIKey, which detects the prefix and
// delegates to the apps table. This avoids a duplicate validation endpoint.
