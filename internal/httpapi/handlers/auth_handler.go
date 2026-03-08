package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuthService describes the auth layer capabilities used by HTTP handlers.
type AuthService interface {
	Register(ctx context.Context, in auth.RegisterInput) (*auth.AuthResult, error)
	Login(ctx context.Context, in auth.LoginInput) (*auth.AuthResult, error)
	Refresh(ctx context.Context, in auth.RefreshInput) (*auth.AuthResult, error)
	Logout(ctx context.Context, sessionID uuid.UUID, jti string, ttl time.Duration) error
	RequestPasswordReset(ctx context.Context, in auth.PasswordResetRequestInput) (string, error)
	ConfirmPasswordReset(ctx context.Context, in auth.PasswordResetConfirmInput) error
	GetUser(ctx context.Context, id uuid.UUID) (*ent.User, error)
	GetUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) (roles []string, permissions []string, err error)
	StartGoogleOAuth(ctx context.Context, in auth.OAuthStartInput) (string, error)
	CompleteGoogleOAuth(ctx context.Context, in auth.OAuthCallbackInput) (*auth.AuthResult, error)
	StartGitHubOAuth(ctx context.Context, in auth.OAuthStartInput) (string, error)
	CompleteGitHubOAuth(ctx context.Context, in auth.OAuthCallbackInput) (*auth.AuthResult, error)
	StartMicrosoftOAuth(ctx context.Context, in auth.OAuthStartInput) (string, error)
	CompleteMicrosoftOAuth(ctx context.Context, in auth.OAuthCallbackInput) (*auth.AuthResult, error)
	ListSessions(ctx context.Context, userID uuid.UUID) ([]*ent.Session, error)
	RevokeSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error
	RevokeAllSessions(ctx context.Context, userID uuid.UUID, exceptSessionID uuid.UUID) error
}

// Logout revokes the current session and token.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	jti := claims.ID
	if jti == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing jti", nil)
		return
	}
	sessionID := parseUUID(claims.SessionID)
	var ttl time.Duration
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl < 0 {
			ttl = 0
		}
	}
	if err := h.service.Logout(r.Context(), sessionID, jti, ttl); err != nil {
		reqID := middleware.GetReqID(r.Context())
		h.logger.Error("logout failed", zap.String("request_id", reqID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "logout failed", map[string]any{"request_id": reqID})
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "bb_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// allowedLogoutRedirectHosts are hosts we allow for post_logout_redirect_uri (open redirect protection).
var allowedLogoutRedirectHosts = []string{
	"theurbanloftcafe.com", "www.theurbanloftcafe.com",
	"ordersapp.codevertexitsolutions.com",
	"accounts.codevertexitsolutions.com", "sso.codevertexitsolutions.com",
	"notifications.codevertexitsolutions.com", "books.codevertexitsolutions.com",
	"localhost",
}

// LogoutGet handles GET /auth/logout?post_logout_redirect_uri=... for browser redirect-based logout (e.g. from cafe-website).
// Does not require auth. Clears session cookie and redirects to post_logout_redirect_uri if allowlisted, else to auth-ui landing.
func (h *AuthHandler) LogoutGet(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")

	// Clear session cookie so the user is logged out on the auth domain
	http.SetCookie(w, &http.Cookie{
		Name:     "bb_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// If we have a valid redirect URI (same-origin or allowlisted), redirect there
	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err == nil && u.Scheme != "" && (u.Scheme == "https" || u.Scheme == "http" && strings.HasPrefix(u.Host, "localhost")) {
			host := strings.ToLower(strings.TrimPrefix(u.Host, "www."))
			for _, allowed := range allowedLogoutRedirectHosts {
				if host == allowed || strings.HasSuffix(host, "."+allowed) {
					http.Redirect(w, r, redirectURI, http.StatusFound)
					return
				}
			}
		}
	}

	// Default: redirect to auth-ui landing (accounts)
	http.Redirect(w, r, "https://accounts.codevertexitsolutions.com", http.StatusFound)
}

// AuthHandler exposes HTTP endpoints for authentication flows.
type AuthHandler struct {
	service AuthService
	logger  *zap.Logger
}

// NewAuthHandler constructs a handler.
func NewAuthHandler(service AuthService, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		service: service,
		logger:  logger,
	}
}

// Register handles user registration requests.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	result, err := h.service.Register(r.Context(), auth.RegisterInput{
		Email:      req.Email,
		Password:   req.Password,
		TenantSlug: req.TenantSlug,
		Profile:    req.Profile,
		IPAddress:  clientIP(r),
		UserAgent:  userAgent(r),
		ClientID:   req.ClientID,
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.toAuthResponse(result))
}

// Login authenticates a user and issues tokens.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	result, err := h.service.Login(r.Context(), auth.LoginInput{
		Email:      req.Email,
		Password:   req.Password,
		TenantSlug: req.TenantSlug,
		ClientID:   req.ClientID,
		IPAddress:  clientIP(r),
		UserAgent:  userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	// Set session cookie for OIDC flows
	http.SetCookie(w, &http.Cookie{
		Name:     "bb_session",
		Value:    result.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // Should be true in production
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour), // Adjust as needed
	})

	writeJSON(w, http.StatusOK, h.toAuthResponse(result))
}

// Refresh exchanges refresh tokens for a new pair.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	result, err := h.service.Refresh(r.Context(), auth.RefreshInput{
		RefreshToken: req.RefreshToken,
		ClientID:     req.ClientID,
		IPAddress:    clientIP(r),
		UserAgent:    userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, h.toAuthResponse(result))
}

// GoogleOAuthStart initiates Google OAuth flow.
func (h *AuthHandler) GoogleOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req googleOAuthStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	authURL, err := h.service.StartGoogleOAuth(r.Context(), auth.OAuthStartInput{
		TenantSlug:  req.TenantSlug,
		ClientID:    req.ClientID,
		Flow:        req.Flow,
		RedirectURI: req.RedirectURI,
		IPAddress:   clientIP(r),
		UserAgent:   userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authorization_url": authURL,
	})
}

// GoogleOAuthCallback finalises Google OAuth login.
func (h *AuthHandler) GoogleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing code or state", nil)
		return
	}

	result, err := h.service.CompleteGoogleOAuth(r.Context(), auth.OAuthCallbackInput{
		Code:      code,
		State:     stateParam,
		IPAddress: clientIP(r),
		UserAgent: userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, h.toAuthResponse(result))
}

// GitHub OAuth
func (h *AuthHandler) GitHubOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req googleOAuthStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	authURL, err := h.service.StartGitHubOAuth(r.Context(), auth.OAuthStartInput{
		TenantSlug:  req.TenantSlug,
		ClientID:    req.ClientID,
		Flow:        req.Flow,
		RedirectURI: req.RedirectURI,
		IPAddress:   clientIP(r),
		UserAgent:   userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorization_url": authURL})
}

func (h *AuthHandler) GitHubOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing code or state", nil)
		return
	}
	result, err := h.service.CompleteGitHubOAuth(r.Context(), auth.OAuthCallbackInput{
		Code:      code,
		State:     stateParam,
		IPAddress: clientIP(r),
		UserAgent: userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toAuthResponse(result))
}

// Microsoft OAuth
func (h *AuthHandler) MicrosoftOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req googleOAuthStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	authURL, err := h.service.StartMicrosoftOAuth(r.Context(), auth.OAuthStartInput{
		TenantSlug:  req.TenantSlug,
		ClientID:    req.ClientID,
		Flow:        req.Flow,
		RedirectURI: req.RedirectURI,
		IPAddress:   clientIP(r),
		UserAgent:   userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authorization_url": authURL})
}

func (h *AuthHandler) MicrosoftOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing code or state", nil)
		return
	}
	result, err := h.service.CompleteMicrosoftOAuth(r.Context(), auth.OAuthCallbackInput{
		Code:      code,
		State:     stateParam,
		IPAddress: clientIP(r),
		UserAgent: userAgent(r),
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toAuthResponse(result))
}

// RequestPasswordReset issues a reset token.
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	token, err := h.service.RequestPasswordReset(r.Context(), auth.PasswordResetRequestInput{
		Email:      req.Email,
		IPAddress:  clientIP(r),
		UserAgent:  userAgent(r),
		TenantSlug: req.TenantSlug,
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"reset_token": token,
		"note":        "In production this token is delivered via notifications service.",
	})
}

// ConfirmPasswordReset consumes a reset token and updates the password.
func (h *AuthHandler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	if err := h.service.ConfirmPasswordReset(r.Context(), auth.PasswordResetConfirmInput{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	}); err != nil {
		h.handleError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

// Me returns the authenticated user profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id in token", nil)
		return
	}

	userEntity, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to load user in /me", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load user", nil)
		return
	}

	roles, permissions, err := h.service.GetUserRolesAndPermissions(r.Context(), userID)
	if err != nil {
		h.logger.Warn("failed to load roles/permissions in /me", zap.Error(err))
		roles = claims.Roles
		permissions = nil
	}
	out := userViewFromEnt(userEntity)
	if out == nil {
		out = make(map[string]any)
	}
	out["roles"] = roles
	out["permissions"] = permissions
	writeJSON(w, http.StatusOK, out)
}

func (h *AuthHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password", nil)
	case errors.Is(err, auth.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found", nil)
	case errors.Is(err, auth.ErrTenantInactive):
		writeError(w, http.StatusForbidden, "tenant_inactive", "tenant is not active", nil)
	case errors.Is(err, auth.ErrPasswordTooWeak):
		writeError(w, http.StatusUnprocessableEntity, "weak_password", "password does not meet requirements", nil)
	case errors.Is(err, auth.ErrPasswordResetTokenInvalid):
		writeError(w, http.StatusBadRequest, "invalid_token", "password reset token invalid or expired", nil)
	case errors.Is(err, auth.ErrEmailAlreadyExists):
		writeError(w, http.StatusConflict, "email_exists", "user with email already exists", nil)
	case errors.Is(err, auth.ErrProviderNotEnabled):
		writeError(w, http.StatusBadRequest, "provider_disabled", "oauth provider not enabled", nil)
	case errors.Is(err, auth.ErrOAuthStateInvalid):
		writeError(w, http.StatusBadRequest, "invalid_state", "oauth state invalid or expired", nil)
	case errors.Is(err, auth.ErrEmailNotVerified):
		writeError(w, http.StatusForbidden, "email_not_verified", "provider email must be verified", nil)
	case errors.Is(err, auth.ErrEmailDomainNotAllowed):
		writeError(w, http.StatusForbidden, "email_domain_blocked", "email domain not allowed", nil)
	default:
		reqID := middleware.GetReqID(r.Context())
		h.logger.Error("auth handler error", zap.String("request_id", reqID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "internal server error", map[string]any{"request_id": reqID})
	}
}

func (h *AuthHandler) toAuthResponse(result *auth.AuthResult) map[string]any {
	userMap := userViewFromEnt(result.User)
	if userMap != nil {
		userMap["roles"] = result.Roles
		userMap["permissions"] = result.Permissions
	}
	return map[string]any{
		"access_token":       result.AccessToken,
		"token_type":         "Bearer",
		"expires_in":         int(time.Until(result.AccessTokenExpiresAt).Seconds()),
		"refresh_token":      result.RefreshToken,
		"refresh_expires_in": int(time.Until(result.RefreshTokenExpiresAt).Seconds()),
		"session_id":         result.SessionID,
		"user":               userMap,
		"tenant":             tenantViewFromEnt(result.Tenant),
		"roles":              result.Roles,
		"permissions":        result.Permissions,
	}
}

func userViewFromEnt(user *ent.User) map[string]any {
	if user == nil {
		return nil
	}
	return map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"status":         user.Status,
		"profile":        user.Profile,
		"last_login_at":  user.LastLoginAt,
		"primary_tenant": user.PrimaryTenantID,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	}
}

func tenantViewFromEnt(tenant *ent.Tenant) map[string]any {
	if tenant == nil {
		return nil
	}
	return map[string]any{
		"id":         tenant.ID,
		"name":       tenant.Name,
		"slug":       tenant.Slug,
		"status":     tenant.Status,
		"metadata":   tenant.Metadata,
		"created_at": tenant.CreatedAt,
		"updated_at": tenant.UpdatedAt,
	}
}

type registerRequest struct {
	Email      string         `json:"email"`
	Password   string         `json:"password"`
	TenantSlug string         `json:"tenant_slug"`
	Profile    map[string]any `json:"profile"`
	ClientID   string         `json:"client_id"`
}

type loginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TenantSlug string `json:"tenant_slug"`
	ClientID   string `json:"client_id"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
}

type passwordResetRequest struct {
	Email      string `json:"email"`
	TenantSlug string `json:"tenant_slug"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type googleOAuthStartRequest struct {
	TenantSlug  string `json:"tenant_slug"`
	ClientID    string `json:"client_id"`
	Flow        string `json:"flow"`
	RedirectURI string `json:"redirect_uri"`
}

// ListSessions returns all active sessions for the authenticated user.
func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id", nil)
		return
	}
	sessions, err := h.service.ListSessions(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to list sessions", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list sessions", nil)
		return
	}
	var result []map[string]any
	for _, s := range sessions {
		result = append(result, map[string]any{
			"id":         s.ID,
			"status":     s.Status,
			"ip_address": s.IPAddress,
			"user_agent": s.UserAgent,
			"issued_at":  s.IssuedAt,
			"expires_at": s.ExpiresAt,
			"is_current": claims.ID == s.ID.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": result})
}

// RevokeSession revokes a specific session for the authenticated user.
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id", nil)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &req); err != nil || req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "session_id required", nil)
		return
	}
	sessionID, err := uuid.Parse(req.SessionID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid session id", nil)
		return
	}
	if err := h.service.RevokeSession(r.Context(), userID, sessionID); err != nil {
		h.logger.Error("failed to revoke session", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to revoke session", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// RevokeAllSessions revokes all sessions except the current one.
func (h *AuthHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid user id", nil)
		return
	}
	// Keep the current session active
	currentSessionID, _ := uuid.Parse(claims.ID)
	if err := h.service.RevokeAllSessions(r.Context(), userID, currentSessionID); err != nil {
		h.logger.Error("failed to revoke all sessions", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to revoke sessions", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "all_revoked"})
}
