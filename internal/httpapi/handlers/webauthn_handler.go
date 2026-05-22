package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	webauthnSvc "github.com/bengobox/auth-api/internal/services/webauthn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// WebAuthnHandler exposes passkey/biometric registration and authentication endpoints.
type WebAuthnHandler struct {
	webAuthn       *webauthnSvc.Service
	authSvc        *auth.Service
	logger         *zap.Logger
	redis          *redis.Client
	redisNamespace string
}

func NewWebAuthnHandler(webAuthn *webauthnSvc.Service, authSvc *auth.Service, logger *zap.Logger, rdb *redis.Client, redisNS string) *WebAuthnHandler {
	return &WebAuthnHandler{webAuthn: webAuthn, authSvc: authSvc, logger: logger, redis: rdb, redisNamespace: redisNS}
}

// BeginRegistration starts the WebAuthn registration ceremony.
// Requires an authenticated user (JWT in Authorization header).
// POST /api/v1/auth/webauthn/register/begin
func (h *WebAuthnHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	userID := parseUUID(claims.Subject)
	if userID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user id", nil)
		return
	}

	var body struct {
		FriendlyName string `json:"friendly_name"`
	}
	_ = decodeJSON(r, &body)

	creation, err := h.webAuthn.BeginRegistration(r.Context(), userID, claims.Email, claims.Email)
	if err != nil {
		h.logger.Error("webauthn begin registration failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to begin registration", nil)
		return
	}

	writeJSON(w, http.StatusOK, creation)
}

// FinishRegistration completes the WebAuthn registration ceremony.
// Requires an authenticated user (JWT in Authorization header).
// POST /api/v1/auth/webauthn/register/finish
func (h *WebAuthnHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	userID := parseUUID(claims.Subject)
	if userID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user id", nil)
		return
	}

	friendlyName := r.URL.Query().Get("name")

	cred, err := h.webAuthn.FinishRegistration(r.Context(), userID, claims.Email, claims.Email, friendlyName, r)
	if err != nil {
		if errors.Is(err, webauthnSvc.ErrSessionExpired) {
			writeError(w, http.StatusUnauthorized, "session_expired", "webauthn session expired, please restart", nil)
			return
		}
		if errors.Is(err, webauthnSvc.ErrRegistrationFailed) {
			writeError(w, http.StatusBadRequest, "registration_failed", "credential verification failed", nil)
			return
		}
		h.logger.Error("webauthn finish registration failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "registration failed", nil)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":            cred.ID.String(),
		"friendly_name": cred.FriendlyName,
		"created_at":    cred.CreatedAt,
	})
}

// BeginAuthentication starts the WebAuthn authentication ceremony.
// Public endpoint — no auth required.
// POST /api/v1/auth/webauthn/authenticate/begin
func (h *WebAuthnHandler) BeginAuthentication(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	_ = decodeJSON(r, &body)

	assertion, sessionKey, err := h.webAuthn.BeginAuthentication(r.Context(), body.Email)
	if err != nil {
		if errors.Is(err, webauthnSvc.ErrUserNotFound) || errors.Is(err, webauthnSvc.ErrNoCredentials) {
			writeError(w, http.StatusNotFound, "not_found", "no credentials registered", nil)
			return
		}
		h.logger.Error("webauthn begin authentication failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to begin authentication", nil)
		return
	}

	// Return the session key so the client can pass it in the finish request.
	w.Header().Set("X-WebAuthn-Session", sessionKey)
	writeJSON(w, http.StatusOK, assertion)
}

// FinishAuthentication completes the WebAuthn authentication ceremony and issues tokens.
// Public endpoint — no auth required.
// POST /api/v1/auth/webauthn/authenticate/finish
func (h *WebAuthnHandler) FinishAuthentication(w http.ResponseWriter, r *http.Request) {
	sessionKey := r.Header.Get("X-WebAuthn-Session")
	if sessionKey == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing X-WebAuthn-Session header", nil)
		return
	}

	tenantSlug := r.URL.Query().Get("tenant")

	userID, err := h.webAuthn.FinishAuthentication(r.Context(), sessionKey, r)
	if err != nil {
		if errors.Is(err, webauthnSvc.ErrSessionExpired) {
			writeError(w, http.StatusUnauthorized, "session_expired", "webauthn session expired, please restart", nil)
			return
		}
		if errors.Is(err, webauthnSvc.ErrAuthenticationFailed) {
			writeError(w, http.StatusUnauthorized, "authentication_failed", "credential verification failed", nil)
			return
		}
		h.logger.Error("webauthn finish authentication failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "authentication failed", nil)
		return
	}

	result, err := h.authSvc.LoginWithWebAuthn(r.Context(), auth.WebAuthnLoginInput{
		UserID:     userID,
		TenantSlug: tenantSlug,
		IPAddress:  r.RemoteAddr,
		UserAgent:  r.Header.Get("User-Agent"),
	})
	if err != nil {
		h.logger.Error("issue session after webauthn failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue session", nil)
		return
	}

	// Store session token in Redis so the auth middleware can resolve bb_session → JWT.
	sessionRef := result.SessionID.String()
	if h.redis != nil && h.redisNamespace != "" {
		sessionKey := h.redisNamespace + ":session_token:" + sessionRef
		ttl := 24 * time.Hour
		if d := time.Until(result.AccessTokenExpiresAt); d > 0 {
			ttl = d
		}
		_ = h.redis.Set(r.Context(), sessionKey, result.AccessToken, ttl).Err()
	}

	// Set bb_session cookie — identical config as AuthHandler.Login so subsequent
	// page loads are authenticated via the session cookie, not just the Bearer token.
	cookie := &http.Cookie{
		Name:     "bb_session",
		Value:    sessionRef,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	if host := r.Host; strings.Contains(host, "codevertexitsolutions.com") {
		cookie.Domain = ".codevertexitsolutions.com"
	}
	http.SetCookie(w, cookie)

	writeJSON(w, http.StatusOK, webAuthnAuthResponse(result))
}

// webAuthnAuthResponse builds the authentication response for WebAuthn logins,
// mirroring toAuthResponse so RBAC state (roles/permissions) is returned to the client.
func webAuthnAuthResponse(result *auth.AuthResult) map[string]any {
	return map[string]any{
		"access_token":       result.AccessToken,
		"token_type":         "Bearer",
		"expires_in":         int(time.Until(result.AccessTokenExpiresAt).Seconds()),
		"refresh_token":      result.RefreshToken,
		"refresh_expires_in": int(time.Until(result.RefreshTokenExpiresAt).Seconds()),
		"session_id":         result.SessionID,
		"user":               userViewFromEnt(result.User),
		"tenant":             tenantViewFromEnt(result.Tenant),
		"roles":              result.Roles,
		"permissions":        result.Permissions,
	}
}

// ListCredentials returns all WebAuthn credentials for the authenticated user.
// GET /api/v1/auth/webauthn/credentials
func (h *WebAuthnHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	userID := parseUUID(claims.Subject)
	creds, err := h.webAuthn.ListCredentials(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list credentials", nil)
		return
	}

	type credResp struct {
		ID           string `json:"id"`
		FriendlyName string `json:"friendly_name,omitempty"`
		CreatedAt    any    `json:"created_at"`
		LastUsedAt   any    `json:"last_used_at,omitempty"`
	}

	out := make([]credResp, 0, len(creds))
	for _, c := range creds {
		out = append(out, credResp{
			ID:           c.ID.String(),
			FriendlyName: c.FriendlyName,
			CreatedAt:    c.CreatedAt,
			LastUsedAt:   c.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": out})
}

// DeleteCredential removes a WebAuthn credential for the authenticated user.
// DELETE /api/v1/auth/webauthn/credentials/{id}
func (h *WebAuthnHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}

	userID := parseUUID(claims.Subject)
	credIDStr := chi.URLParam(r, "id")
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid credential id", nil)
		return
	}

	if err := h.webAuthn.DeleteCredential(r.Context(), userID, credID); err != nil {
		if err.Error() == "credential not found" {
			writeError(w, http.StatusNotFound, "not_found", "credential not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete credential", nil)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
