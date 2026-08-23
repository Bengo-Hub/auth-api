package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/app"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// InternalServiceKeyScope is the reserved scope tag marking the platform App
// that mirrors the fleet's shared INTERNAL_SERVICE_KEY S2S credential. Tagging
// it this way (rather than a dedicated boolean column) means it shows up
// clearly in the Apps & Keys UI and can be rotated/suspended like any other
// app, without a schema change.
const InternalServiceKeyScope = "internal_service_key"

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
	// TenantID lets a platform admin issue a "tenant"-type app scoped to a
	// TARGET tenant other than their own (e.g. handing an external API-partner
	// tenant its eTIMS API credential from the platform-owner console). Ignored
	// (and the caller's own claims.TenantID used, as before) unless the caller
	// passes requirePlatformAdmin — an ordinary tenant admin can still only ever
	// create an app under their own tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

type AppResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	AppType     string    `json:"app_type"`
	Environment string    `json:"environment"`
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

// tenantDeveloperRoles mirrors auth-ui's DashboardSidebar.tsx DEVELOPER_PORTAL_ROLES —
// keep both lists in sync. These are ordinary TenantMembership role strings (tenant-scoped,
// NOT platform-wide — see requirePlatformAdmin above for that distinction).
var tenantDeveloperRoles = map[string]bool{
	"admin":     true,
	"owner":     true,
	"superuser": true,
	"developer": true,
}

// hasTenantDeveloperRole reports whether claims carry a tenant-scoped role entitled to
// manage the caller's own tenant's Apps (Developer Portal). Does not check platform
// ownership — callers must separately check requirePlatformAdmin for the platform-wide
// bypass, matching every other access check in this file. Without this check, any
// authenticated member of a tenant (even a cashier with zero elevated permissions) could
// create/list/manage tenant Apps despite the "tenant apps require admin+" intent below.
func hasTenantDeveloperRole(claims *token.Claims) bool {
	for _, r := range claims.Roles {
		if tenantDeveloperRoles[r] {
			return true
		}
	}
	return false
}

// reservedPlatformScopes are cross-tenant trust markers that must never appear on a
// tenant-scoped app, no matter who creates it — a tenant app carrying one would be
// functionally indistinguishable from the shared platform S2S credential
// (INTERNAL_SERVICE_KEY), defeating the platform/tenant app_type split. Apps that
// genuinely need this level of trust belong under app_type "platform" instead, which
// is already gated to platform admins by requirePlatformAdmin above.
var reservedPlatformScopes = map[string]bool{
	InternalServiceKeyScope: true,
	"admin":                 true,
	"auth.admin":            true,
}

// allowedTenantScopePrefixes are the service APIs a tenant-scoped app may request
// access to — one scope per service surface, never a platform-wide grant. Extend this
// list, not the reserved-scope escape hatch, when a new service gains its own API.
var allowedTenantScopePrefixes = []string{
	"treasury:",
	"etims:",
	"notifications:",
	"subscriptions:",
	"auth:",
	"sso:",
}

// validateTenantAppScopes rejects any scope on a tenant-type app that isn't tied to a
// known, single service surface. Applies equally to self-service tenant admins and to a
// platform admin creating/editing an app on a tenant's behalf — cross-tenant/system trust
// scopes belong on a platform-type app, never a tenant one.
func validateTenantAppScopes(scopes []string) error {
	var grantedPrefix string
	for _, s := range scopes {
		if reservedPlatformScopes[s] || strings.HasPrefix(s, "s2s:") || strings.HasPrefix(s, "s2s.") || s == "s2s" {
			return fmt.Errorf("scope %q is platform-admin-only and cannot be granted to a tenant app", s)
		}
		matched := ""
		for _, prefix := range allowedTenantScopePrefixes {
			if strings.HasPrefix(s, prefix) {
				matched = prefix
				break
			}
		}
		if matched == "" {
			return fmt.Errorf("scope %q is not a recognized service scope (expected one of: treasury:*, notifications:*, subscriptions:*, sso:*)", s)
		}
		// A tenant app is always limited to ONE service, never a bundle of several -- matches the
		// self-serve create-app UI's own single-service picker. A caller building a hand-crafted
		// request with scopes spanning two service prefixes (e.g. ["treasury:read",
		// "notifications:read"]) is rejected here rather than silently accepted, closing a gap
		// where this was previously only a UI convention, not a server-side rule.
		if grantedPrefix == "" {
			grantedPrefix = matched
		} else if grantedPrefix != matched {
			return fmt.Errorf("a tenant app may only be scoped to one service — found both %q and %q scopes in the same request", grantedPrefix, matched)
		}
	}
	return nil
}

func appToResponse(a *ent.App) AppResponse {
	resp := AppResponse{
		ID:          a.ID.String(),
		Name:        a.Name,
		Description: a.Description,
		AppType:     string(a.AppType),
		Environment: string(a.Environment),
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
	if appType == app.AppTypeTenant {
		if !requirePlatformAdmin(claims) && !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required to create tenant apps", nil)
			return
		}
		if err := validateTenantAppScopes(req.Scopes); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_scope", err.Error(), nil)
			return
		}
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
		targetTenant := claims.TenantID
		if req.TenantID != "" && req.TenantID != claims.TenantID {
			if !requirePlatformAdmin(claims) {
				writeError(w, http.StatusForbidden, "forbidden", "platform admin required to scope an app to another tenant", nil)
				return
			}
			targetTenant = req.TenantID
		}
		if tenantID, err := uuid.Parse(targetTenant); err == nil {
			create.SetTenantID(tenantID)
		} else if req.TenantID != "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
			return
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

	if !requirePlatformAdmin(claims) && !hasTenantDeveloperRole(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
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
	if !requirePlatformAdmin(claims) {
		if a.TenantID == nil || a.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
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
	if !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
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
	if existing.AppType == app.AppTypeTenant && req.Scopes != nil {
		if err := validateTenantAppScopes(req.Scopes); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_scope", err.Error(), nil)
			return
		}
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
	if !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
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
	if !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
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
	if existing.AppType == app.AppTypeTenant && !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
	}

	if err := h.ent.App.DeleteOneID(appID).Exec(r.Context()); err != nil {
		h.logger.Error("delete app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete app", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SuspendApp temporarily disables an app's token without the permanence of Revoke.
// A suspended app can later be reactivated via ResumeApp; a revoked one cannot.
func (h *AppHandler) SuspendApp(w http.ResponseWriter, r *http.Request) {
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
	if !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
	}
	if existing.Status != app.StatusActive {
		writeError(w, http.StatusConflict, "invalid_state", "only an active app can be suspended", nil)
		return
	}
	updated, err := h.ent.App.UpdateOneID(appID).SetStatus(app.StatusSuspended).Save(r.Context())
	if err != nil {
		h.logger.Error("suspend app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to suspend app", nil)
		return
	}
	h.logger.Info("app suspended", zap.String("app_id", appID.String()), zap.String("suspended_by", claims.Subject))
	writeJSON(w, http.StatusOK, appToResponse(updated))
}

// ResumeApp reactivates a suspended app's token. Has no effect on revoked/expired apps.
func (h *AppHandler) ResumeApp(w http.ResponseWriter, r *http.Request) {
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
	if !requirePlatformAdmin(claims) {
		if existing.TenantID == nil || existing.TenantID.String() != claims.TenantID {
			writeError(w, http.StatusForbidden, "forbidden", "access denied", nil)
			return
		}
		if !hasTenantDeveloperRole(claims) {
			writeError(w, http.StatusForbidden, "forbidden", "admin, owner, superuser, or developer role required", nil)
			return
		}
	}
	if existing.Status != app.StatusSuspended {
		writeError(w, http.StatusConflict, "invalid_state", "only a suspended app can be resumed", nil)
		return
	}
	updated, err := h.ent.App.UpdateOneID(appID).SetStatus(app.StatusActive).Save(r.Context())
	if err != nil {
		h.logger.Error("resume app", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to resume app", nil)
		return
	}
	h.logger.Info("app resumed", zap.String("app_id", appID.String()), zap.String("resumed_by", claims.Subject))
	writeJSON(w, http.StatusOK, appToResponse(updated))
}

// PromoteToProduction switches a sandbox App to production, unlocking live API access for its
// holder. Platform-admin-only "manual v1" gate — a real automated per-service go-live review
// (like the eTIMS certification checklist in treasury-api) is future work generalizing that
// pattern across the developer portal; for now a human reviews the request out-of-band and
// promotes by hand. One-way: there is no demote-to-sandbox action, mirroring how a production
// credential elsewhere in the fleet is never silently downgraded.
func (h *AppHandler) PromoteToProduction(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	if !requirePlatformAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "platform admin required to promote an app to production", nil)
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
	if existing.Environment == app.EnvironmentProduction {
		writeError(w, http.StatusConflict, "invalid_state", "app is already in production", nil)
		return
	}
	if existing.Status != app.StatusActive {
		writeError(w, http.StatusConflict, "invalid_state", "only an active app can be promoted", nil)
		return
	}
	updated, err := h.ent.App.UpdateOneID(appID).SetEnvironment(app.EnvironmentProduction).Save(r.Context())
	if err != nil {
		h.logger.Error("promote app to production", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to promote app", nil)
		return
	}
	h.logger.Info("app promoted to production", zap.String("app_id", appID.String()), zap.String("promoted_by", claims.Subject))
	writeJSON(w, http.StatusOK, appToResponse(updated))
}

// IsValidInternalServiceToken reports whether the given X-API-Key value matches an
// active, unexpired platform App carrying InternalServiceKeyScope. This is the
// dual-mode companion to the static INTERNAL_SERVICE_KEY env-var compare
// (requireInternalKey in router.go): it lets a platform admin manage/rotate/suspend
// the fleet's shared internal-service credential through the same Apps & Keys CRUD
// as any other app, without requiring the other services (which still compare the
// static env var directly, by design — S2S auth there must keep working even when
// auth-api itself is down) to change in this same pass.
func (h *AppHandler) IsValidInternalServiceToken(ctx context.Context, tokenStr string) bool {
	if tokenStr == "" {
		return false
	}
	a, err := h.ent.App.Query().
		Where(app.KeyHashEQ(hashAPIKey(tokenStr)), app.StatusEQ(app.StatusActive)).
		Only(ctx)
	if err != nil {
		return false
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.IsZero() && time.Now().After(*a.ExpiresAt) {
		return false
	}
	if a.AppType != app.AppTypePlatform {
		return false // defense in depth: internal_service_key trust is platform-app-only
	}
	for _, s := range a.Scopes {
		if s == InternalServiceKeyScope {
			return true
		}
	}
	return false
}

// ValidateAppToken is intentionally absent: validation of bng_app_* tokens
// is handled by APIKeyHandler.ValidateAPIKey, which detects the prefix and
// delegates to the apps table. This avoids a duplicate validation endpoint.
