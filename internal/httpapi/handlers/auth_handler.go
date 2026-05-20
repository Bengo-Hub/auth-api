package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/services/integrations"
	"github.com/bengobox/auth-api/internal/services/usecase"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
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
	GetTenant(ctx context.Context, id uuid.UUID) (*ent.Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*ent.Tenant, error)
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
	IsMFAEnabled(ctx context.Context, userID uuid.UUID) (bool, error)
	ListUserTenantMemberships(ctx context.Context, userID uuid.UUID) ([]*ent.TenantMembership, error)
	AcceptTerms(ctx context.Context, userID uuid.UUID) error
	ChangePassword(ctx context.Context, in auth.ChangePasswordInput) error
}

// UseCaseService describes the use case logic capabilities.
type UseCaseService interface {
	ResolveConfig(ctx context.Context, useCase string) *usecase.Config
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

	// Clear session cookie (Domain must match how it was set so browser clears it on .codevertexitsolutions.com)
	http.SetCookie(w, &http.Cookie{
		Name:     "bb_session",
		Value:    "",
		Path:     "/",
		Domain:   h.cookieDomain,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// allowedLogoutRedirectHosts returns hosts allowed for post_logout_redirect_uri.
// Configured via AUTH_SECURITY_LOGOUT_REDIRECT_HOSTS env var; falls back to handler's config.
func (h *AuthHandler) allowedLogoutRedirectHosts() []string {
	if len(h.logoutRedirectHosts) > 0 {
		return h.logoutRedirectHosts
	}
	return []string{"localhost"}
}

// LogoutGet handles GET /auth/logout?post_logout_redirect_uri=... for browser redirect-based logout (e.g. from cafe-website).
// Does not require auth. Clears session cookie and redirects to post_logout_redirect_uri if allowlisted, else to auth-ui landing.
func (h *AuthHandler) LogoutGet(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")

	// Clear session cookie (Domain must match how it was set so browser clears it on .codevertexitsolutions.com)
	http.SetCookie(w, &http.Cookie{
		Name:     "bb_session",
		Value:    "",
		Path:     "/",
		Domain:   h.cookieDomain,
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
			for _, allowed := range h.allowedLogoutRedirectHosts() {
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

// integrationMeta maps an integration name to its category and presentation hints.
// Keep this aligned with auth-ui/src/lib/oauth/catalog.ts so that the frontend
// can render consistent logos and filter by category without extra round-trips.
var integrationMeta = map[string]struct {
	Category  string
	LogoSlug  string
	BrandHex  string
}{
	"google":    {Category: "oauth", LogoSlug: "google", BrandHex: "#4285F4"},
	"microsoft": {Category: "oauth", LogoSlug: "microsoft", BrandHex: "#2F2F2F"},
	"github":    {Category: "oauth", LogoSlug: "github", BrandHex: "#181717"},
}

func (h *AuthHandler) ListActiveIntegrations(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.URL.Query().Get("tenant_slug")
	category := r.URL.Query().Get("category") // optional filter: "oauth", "messaging", etc.
	var tenantID *uuid.UUID

	// OAuth identity providers are platform-level by policy: every tenant
	// authenticates through the same Google/Microsoft/GitHub app, with tenant
	// context carried in the signed state payload. Ignore any tenant_slug
	// hint when the caller is asking for the oauth category so the response
	// can't accidentally include a misconfigured tenant-scoped row.
	if tenantSlug != "" && category != "oauth" {
		tenant, err := h.service.GetTenantBySlug(r.Context(), tenantSlug)
		if err == nil && tenant != nil {
			tenantID = &tenant.ID
		}
	}

	configs, err := h.integrations.ListActiveIntegrations(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list integrations", nil)
		return
	}

	type integrationInfo struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Category    string `json:"category,omitempty"`
		LogoSlug    string `json:"logo_slug,omitempty"`
		BrandColor  string `json:"brand_color,omitempty"`
	}

	response := make([]integrationInfo, 0, len(configs))
	for _, c := range configs {
		meta := integrationMeta[c.Name]
		if category != "" && meta.Category != category {
			continue
		}
		response = append(response, integrationInfo{
			Name:        c.Name,
			DisplayName: c.DisplayName,
			Category:    meta.Category,
			LogoSlug:    meta.LogoSlug,
			BrandColor:  meta.BrandHex,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

// AuthHandler exposes HTTP endpoints for authentication flows.
type AuthHandler struct {
	service             AuthService
	integrations        *integrations.Service
	usecase             UseCaseService
	logger              *zap.Logger
	redis               *redis.Client
	redisNamespace      string
	cookieDomain        string
	logoutRedirectHosts []string
}

// NewAuthHandler constructs a handler. redis and redisNamespace are optional; when set, GET /auth/me responses are cached with TTL = token expiry.
func NewAuthHandler(service AuthService, integrationSvc *integrations.Service, usecaseSvc UseCaseService, logger *zap.Logger, redis *redis.Client, redisNamespace string, cookieDomain string, logoutRedirectHosts []string) *AuthHandler {
	if cookieDomain == "" {
		cookieDomain = ".codevertexitsolutions.com"
	}
	return &AuthHandler{
		service:             service,
		integrations:        integrationSvc,
		usecase:             usecaseSvc,
		logger:              logger,
		redis:               redis,
		redisNamespace:      redisNamespace,
		cookieDomain:        cookieDomain,
		logoutRedirectHosts: logoutRedirectHosts,
	}
}

// Register handles user registration requests.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	var newOrg *auth.NewOrgInput
	if req.NewOrg != nil {
		newOrg = &auth.NewOrgInput{
			Name:         req.NewOrg.Name,
			Slug:         req.NewOrg.Slug,
			UseCase:      req.NewOrg.UseCase,
			UseCases:     req.NewOrg.UseCases,
			HQBranchName: req.NewOrg.HQBranchName,
			Metadata:     req.NewOrg.Metadata,
		}
	}

	result, err := h.service.Register(r.Context(), auth.RegisterInput{
		Email:         req.Email,
		Password:      req.Password,
		TenantSlug:    req.TenantSlug,
		Profile:       req.Profile,
		IPAddress:     clientIP(r),
		UserAgent:     userAgent(r),
		ClientID:      req.ClientID,
		SelectedPlan:  req.SelectedPlan,
		OrgAction:     req.OrgAction,
		NewOrg:        newOrg,
		Role:          req.Role,
		TermsAccepted: req.TermsAccepted,
	})
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.toAuthResponse(result))
}

// RegisterOAuth completes registration for a new user arriving via OAuth2 flow.
// The signup wizard submits an oauth_token (issued during the OAuth callback)
// together with org-selection details to finalise account creation without a password.
func (h *AuthHandler) RegisterOAuth(w http.ResponseWriter, r *http.Request) {
	var req oauthRegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}

	if req.OAuthToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "oauth_token is required", nil)
		return
	}

	var newOrg *auth.NewOrgInput
	if req.NewOrg != nil {
		newOrg = &auth.NewOrgInput{
			Name:         req.NewOrg.Name,
			Slug:         req.NewOrg.Slug,
			UseCase:      req.NewOrg.UseCase,
			UseCases:     req.NewOrg.UseCases,
			HQBranchName: req.NewOrg.HQBranchName,
			Metadata:     req.NewOrg.Metadata,
		}
	}

	result, err := h.service.Register(r.Context(), auth.RegisterInput{
		Email:         req.Email,
		Password:      "",  // OAuth users have no password; hash is not set
		TenantSlug:    req.TenantSlug,
		Profile:       req.Profile,
		IPAddress:     clientIP(r),
		UserAgent:     userAgent(r),
		ClientID:      req.ClientID,
		SelectedPlan:  req.SelectedPlan,
		OrgAction:     req.OrgAction,
		NewOrg:        newOrg,
		TermsAccepted: req.TermsAccepted,
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

	// MFA enforcement: if TOTP is enabled, require code before issuing tokens.
	// When totp_code is not provided, return mfa_required so the frontend
	// can show the TOTP input and re-submit with the code included.
	if mfaEnabled, _ := h.service.IsMFAEnabled(r.Context(), result.User.ID); mfaEnabled {
		if req.TOTPCode == "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"mfa_required": true,
				"mfa_method":   "totp",
				"user_id":      result.User.ID.String(),
			})
			return
		}
		// Validate the provided TOTP code via the MFA service.
		// The MFA service is accessed through the auth service's entClient.
		totpRec, totpErr := result.User.QueryMfaTotp().Only(r.Context())
		if totpErr != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to load TOTP config", nil)
			return
		}
		if !totp.Validate(req.TOTPCode, totpRec.Secret) {
			writeError(w, http.StatusUnauthorized, "invalid_totp", "invalid TOTP code", nil)
			return
		}
	}

	// Cache the login result for /me optimization (TTL = token expiry or 24h)
	if h.redis != nil && h.redisNamespace != "" {
		cacheKey := h.redisNamespace + ":auth:me:" + result.User.ID.String()
		ttl := 24 * time.Hour
		if !result.AccessTokenExpiresAt.IsZero() {
			if d := time.Until(result.AccessTokenExpiresAt); d > 0 {
				ttl = d
			}
		}
		
		// Build the "me" view for the cache
		out := userViewFromEnt(result.User)
		if out == nil {
			out = make(map[string]any)
		}
		out["roles"] = result.Roles
		out["permissions"] = result.Permissions
		if mfaOn, _ := h.service.IsMFAEnabled(r.Context(), result.User.ID); mfaOn {
			out["mfa_enabled"] = true
		} else {
			out["mfa_enabled"] = false
		}
		if result.Tenant != nil {
			out["tenant"] = tenantViewFromEnt(result.Tenant)
			out["tenant_id"] = result.Tenant.ID.String()
			out["tenant_slug"] = result.Tenant.Slug
			if result.Tenant.Slug == "codevertex" {
				out["is_platform_owner"] = true
			}
		}

		if b, err := json.Marshal(out); err == nil && ttl > 0 {
			_ = h.redis.Set(r.Context(), cacheKey, b, ttl).Err()
		}
	}

	// Set session cookie for OIDC flows. Store only the session ID (36 bytes)
	// in the cookie — the full JWT (can be >4KB for admin users with many
	// permissions) is kept in Redis. The auth middleware resolves session ID → JWT.
	sessionRef := result.SessionID.String()
	if h.redis != nil && h.redisNamespace != "" {
		sessionKey := h.redisNamespace + ":session_token:" + sessionRef
		ttl := 24 * time.Hour
		if !result.AccessTokenExpiresAt.IsZero() {
			if d := time.Until(result.AccessTokenExpiresAt); d > 0 {
				ttl = d
			}
		}
		_ = h.redis.Set(r.Context(), sessionKey, result.AccessToken, ttl).Err()
	}
	cookie := &http.Cookie{
		Name:     "bb_session",
		Value:    sessionRef,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	if host := r.Host; host != "" && (strings.Contains(host, "codevertexitsolutions.com") || strings.HasSuffix(host, ".codevertexitsolutions.com")) {
		cookie.Domain = ".codevertexitsolutions.com"
	}
	http.SetCookie(w, cookie)

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

// oauthFrontendBaseURL returns the base URL of the auth-ui frontend used for
// post-OAuth redirects. Derived from the cookie domain — if we're on
// codevertexitsolutions.com, the frontend is accounts.codevertexitsolutions.com.
func (h *AuthHandler) oauthFrontendBaseURL(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, "codevertexitsolutions.com") {
		return "https://accounts.codevertexitsolutions.com"
	}
	return "http://localhost:3000"
}

// handleOAuthCallback is the shared logic for all provider callbacks. It:
//  1. Checks for ?error= from the provider (user cancelled) → redirect to login
//  2. Exchanges code, creates/links user, issues session
//  3. Sets the bb_session cookie (same as Login handler)
//  4. Redirects (302) to the frontend /auth/callback which finalises the login
func (h *AuthHandler) handleOAuthCallback(
	w http.ResponseWriter,
	r *http.Request,
	provider string,
	complete func(context.Context, auth.OAuthCallbackInput) (*auth.AuthResult, error),
) {
	frontendBase := h.oauthFrontendBaseURL(r)

	// Provider-side errors (user cancelled, admin denied, etc.)
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		desc := r.URL.Query().Get("error_description")
		if desc == "" {
			desc = errCode
		}
		target := frontendBase + "/login?oauth_error=" + url.QueryEscape(desc)
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		http.Redirect(w, r, frontendBase+"/login?oauth_error=missing+code+or+state", http.StatusFound)
		return
	}

	result, err := complete(r.Context(), auth.OAuthCallbackInput{
		Code:      code,
		State:     stateParam,
		IPAddress: clientIP(r),
		UserAgent: userAgent(r),
	})
	if err != nil {
		h.logger.Error("oauth callback failed", zap.String("provider", provider), zap.Error(err))
		http.Redirect(w, r, frontendBase+"/login?oauth_error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	// Set session cookie (mirrors Login handler logic).
	sessionRef := result.SessionID.String()
	if h.redis != nil && h.redisNamespace != "" {
		sessionKey := h.redisNamespace + ":session_token:" + sessionRef
		ttl := 24 * time.Hour
		if !result.AccessTokenExpiresAt.IsZero() {
			if d := time.Until(result.AccessTokenExpiresAt); d > 0 {
				ttl = d
			}
		}
		_ = h.redis.Set(r.Context(), sessionKey, result.AccessToken, ttl).Err()
	}
	cookie := &http.Cookie{
		Name:     "bb_session",
		Value:    sessionRef,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	if host := r.Host; host != "" && (strings.Contains(host, "codevertexitsolutions.com") || strings.HasSuffix(host, ".codevertexitsolutions.com")) {
		cookie.Domain = ".codevertexitsolutions.com"
	}
	http.SetCookie(w, cookie)

	// Redirect to frontend callback page. It reads the session cookie via
	// /api/v1/auth/me and stores the user in the auth store.
	target := frontendBase + "/auth/callback"
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *AuthHandler) GoogleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	h.handleOAuthCallback(w, r, "google", func(ctx context.Context, in auth.OAuthCallbackInput) (*auth.AuthResult, error) {
		return h.service.CompleteGoogleOAuth(ctx, in)
	})
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
	h.handleOAuthCallback(w, r, "github", func(ctx context.Context, in auth.OAuthCallbackInput) (*auth.AuthResult, error) {
		return h.service.CompleteGitHubOAuth(ctx, in)
	})
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
	h.handleOAuthCallback(w, r, "microsoft", func(ctx context.Context, in auth.OAuthCallbackInput) (*auth.AuthResult, error) {
		return h.service.CompleteMicrosoftOAuth(ctx, in)
	})
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

// Me returns the authenticated user profile including the primary tenant object.
// When Redis is configured, the response is cached by user ID with TTL = token expiry (or 24h) to reduce DB load.
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

	// Cache key includes the token's issued-at so new tokens (issued after a subscription
	// change or renewal) always get a fresh response rather than hitting stale cached data.
	cacheKey := ""
	if h.redis != nil && h.redisNamespace != "" {
		iat := int64(0)
		if claims.IssuedAt != nil {
			iat = claims.IssuedAt.Unix()
		}
		cacheKey = fmt.Sprintf("%s:auth:me:%s:%d", h.redisNamespace, userID.String(), iat)
		if cached, err := h.redis.Get(r.Context(), cacheKey).Bytes(); err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(cached)
			return
		}
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

	// MFA status
	if mfaEnabled, err := h.service.IsMFAEnabled(r.Context(), userID); err == nil {
		out["mfa_enabled"] = mfaEnabled
	}

	// Resolve and embed the primary tenant as a nested object so frontend
	// useAuth and test_sso_me_endpoint can read tenant.id / tenant.slug directly.
	if userEntity.PrimaryTenantID != "" {
		if tenantID, parseErr := uuid.Parse(userEntity.PrimaryTenantID); parseErr == nil {
			if tenantEntity, tErr := h.service.GetTenant(r.Context(), tenantID); tErr == nil {
				tenantView := tenantViewFromEnt(tenantEntity)
				// Inject subscription_features from JWT claims (not stored in DB).
				// JWT is the freshest source; decoding avoids a round-trip to subscription-api.
				if len(claims.SubscriptionFeatures) > 0 {
					tenantView["subscription_features"] = claims.SubscriptionFeatures
				}
				// Compute grace_period_ends_at so the frontend doesn't need to hard-code the 7-day rule.
				if tenantEntity.SubscriptionExpiresAt != nil {
					graceEnd := tenantEntity.SubscriptionExpiresAt.Add(7 * 24 * time.Hour)
					tenantView["subscription_grace_ends_at"] = graceEnd
				}
				out["tenant"] = tenantView
				out["tenant_id"] = tenantEntity.ID.String()
				out["tenant_slug"] = tenantEntity.Slug
				if tenantEntity.Slug == "codevertex" {
					out["is_platform_owner"] = true
				}
			} else {
				h.logger.Warn("failed to load primary tenant in /me", zap.Error(tErr))
			}
		}
	}

	// Include every tenant the user is a member of (with roles per tenant).
	// The frontend uses this to: (a) populate the tenant switcher so
	// activeTenant matches the user's ACTUAL org, not necessarily the
	// platform-owner primary, (b) show an accurate org count on the overview.
	memberships, mErr := h.service.ListUserTenantMemberships(r.Context(), userID)
	if mErr != nil {
		h.logger.Warn("failed to load memberships in /me", zap.Error(mErr))
	}
	if memberships != nil {
		tenants := make([]map[string]any, 0, len(memberships))
		for _, m := range memberships {
			t := m.Edges.Tenant
			if t == nil || t.Status != "active" {
				continue
			}
			tenants = append(tenants, map[string]any{
				"id":           t.ID.String(),
				"name":         t.Name,
				"slug":         t.Slug,
				"brand_colors": t.BrandColors,
				"logo_url":     t.LogoURL,
				"roles":        m.Roles,
			})
		}
		out["tenants"] = tenants
	}

	if cacheKey != "" {
		ttl := 24 * time.Hour
		if claims.ExpiresAt != nil {
			if d := time.Until(claims.ExpiresAt.Time); d > 0 {
				ttl = d
			}
		}
		if b, err := json.Marshal(out); err == nil && ttl > 0 {
			_ = h.redis.Set(r.Context(), cacheKey, b, ttl).Err()
		}
	}

	writeJSON(w, http.StatusOK, out)
}

// AcceptTerms marks the authenticated user as having accepted the platform terms of service.
func (h *AuthHandler) AcceptTerms(w http.ResponseWriter, r *http.Request) {
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

	if err := h.service.AcceptTerms(r.Context(), userID); err != nil {
		h.logger.Error("failed to accept terms", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to accept terms", nil)
		return
	}

	// Invalidate /me cache so the next request reflects updated terms_accepted.
	if h.redis != nil && h.redisNamespace != "" {
		cacheKey := h.redisNamespace + ":auth:me:" + userID.String()
		_ = h.redis.Del(r.Context(), cacheKey).Err()
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GetUseCaseConfig returns the configuration for a given use case or the current tenant's use case.
func (h *AuthHandler) GetUseCaseConfig(w http.ResponseWriter, r *http.Request) {
	useCase := r.URL.Query().Get("use_case")

	// If no use_case provided, try to resolve from current tenant in context
	if useCase == "" {
		claims, ok := authmiddleware.ClaimsFromContext(r.Context())
		if ok && claims.TenantSlug != "" {
			tenant, err := h.service.GetTenantBySlug(r.Context(), claims.TenantSlug)
			if err == nil && tenant != nil && tenant.UseCase != nil {
				useCase = *tenant.UseCase
			}
		}
	}

	if useCase == "" {
		useCase = "other"
	}

	config := h.usecase.ResolveConfig(r.Context(), useCase)
	writeJSON(w, http.StatusOK, config)
}

func (h *AuthHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	// Check for TenantMismatchError first (it's a struct error, not a sentinel).
	var mismatchErr *auth.TenantMismatchError
	if errors.As(err, &mismatchErr) {
		writeError(w, http.StatusForbidden, "tenant_mismatch",
			"you do not have access to the requested organisation",
			map[string]any{
				"requested_tenant": mismatchErr.RequestedSlug,
				"user_tenants":     mismatchErr.UserTenants,
			})
		return
	}

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

// toAuthResponse builds the login/register/refresh response. Roles and permissions are only at top level
// to avoid duplicate keys (do not set them on user object).
func (h *AuthHandler) toAuthResponse(result *auth.AuthResult) map[string]any {
	userMap := userViewFromEnt(result.User)
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
		"id":               user.ID,
		"email":            user.Email,
		"status":           user.Status,
		"profile":          user.Profile,
		"last_login_at":    user.LastLoginAt,
		"primary_tenant":   user.PrimaryTenantID,
		"created_at":       user.CreatedAt,
		"updated_at":       user.UpdatedAt,
		"terms_accepted":   user.TermsAccepted,
		"terms_accepted_at": user.TermsAcceptedAt,
	}
}

func tenantViewFromEnt(tenant *ent.Tenant) map[string]any {
	if tenant == nil {
		return nil
	}

	brandColors := tenant.BrandColors
	if brandColors == nil || len(brandColors) == 0 {
		brandColors = map[string]any{
			"primary":   "#5B1C4D",
			"secondary": "#ea8022",
			"accent":    "#f36a0c",
		}
	}

	logoURL := tenant.LogoURL
	if logoURL == nil || *logoURL == "" {
		logoURL = strPtr("https://accounts.codevertexitsolutions.com/images/logo/codevertex.png")
	}

	return map[string]any{
		"id":                      tenant.ID,
		"name":                    tenant.Name,
		"slug":                    tenant.Slug,
		"status":                  tenant.Status,
		"logo_url":                logoURL,
		"brand_colors":            brandColors,
		"contact_email":           tenant.ContactEmail,
		"website":                 tenant.Website,
		"country":                 tenant.Country,
		"timezone":                tenant.Timezone,
		"subscription_plan":       tenant.SubscriptionPlan,
		"subscription_status":     tenant.SubscriptionStatus,
		"subscription_expires_at": tenant.SubscriptionExpiresAt,
		"tier_limits":             tenant.TierLimits,
		"created_at":              tenant.CreatedAt,
		"updated_at":              tenant.UpdatedAt,
	}
}

func strPtr(s string) *string {
	return &s
}

type newOrgRequest struct {
	Name         string         `json:"name"`
	Slug         string         `json:"slug"`
	UseCase      string         `json:"use_case"`       // Legacy single value
	UseCases     []string       `json:"use_cases"`      // Multi-select use cases
	HQBranchName string         `json:"hq_branch_name"` // e.g. "Main/HQ"
	Metadata     map[string]any `json:"metadata,omitempty"`
}

type registerRequest struct {
	Email      string         `json:"email"`
	Password   string         `json:"password"`
	TenantSlug string         `json:"tenant_slug"`
	Profile    map[string]any `json:"profile"`
	ClientID   string         `json:"client_id"`
	// SelectedPlan is REQUIRED at registration time. The plan code (e.g. "STARTER", "GROWTH",
	// "PROFESSIONAL") is recorded on the new tenant so subscription-api can create the trial
	// subscription. The user MUST have selected a plan in the signup wizard before submitting.
	SelectedPlan string `json:"selected_plan,omitempty"`
	// OrgAction is "join_existing" (default) or "create_new".
	// When "create_new", NewOrg must be populated and the registering user
	// becomes the tenant admin for the new organisation.
	OrgAction string         `json:"org_action,omitempty"`
	NewOrg    *newOrgRequest `json:"new_org,omitempty"`
	// Role is an optional role hint for pre-invited users (e.g. "driver" for fleet invitations).
	Role string `json:"role,omitempty"`
	// TermsAccepted records whether the user accepted the Terms of Service at signup.
	TermsAccepted bool `json:"terms_accepted"`
}

type loginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	TenantSlug string `json:"tenant_slug"`
	ClientID   string `json:"client_id"`
	TOTPCode   string `json:"totp_code,omitempty"`
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
	// ReturnTo is a frontend-only hint for where to land after the callback.
	// Accepted so the DisallowUnknownFields JSON decoder doesn't 400 on requests
	// from auth-ui; the server ignores it — the redirect destination is derived
	// from the OAuthClient's registered redirect_uris.
	ReturnTo string `json:"return_to"`
}

// oauthRegisterRequest is submitted by the signup wizard after an OAuth2 provider
// redirected a new (unregistered) user to /signup with pre-filled details.
// The oauth_token is a short-lived token issued by auth-api during the OAuth
// callback to let the signup wizard prove the identity claim.
type oauthRegisterRequest struct {
	Email         string         `json:"email"`
	OAuthProvider string         `json:"oauth_provider"` // e.g. "google", "github", "microsoft"
	OAuthToken    string         `json:"oauth_token"`    // short-lived token from auth-api OAuth callback
	TenantSlug    string         `json:"tenant_slug"`
	Profile       map[string]any `json:"profile"`
	ClientID      string         `json:"client_id"`
	SelectedPlan  string         `json:"selected_plan,omitempty"`
	OrgAction     string         `json:"org_action,omitempty"`
	NewOrg        *newOrgRequest `json:"new_org,omitempty"`
	TermsAccepted bool           `json:"terms_accepted"`
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

// ChangePassword lets an authenticated user change their own password by supplying the current one.
// POST /api/v1/auth/me/change-password
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "current_password and new_password are required", nil)
		return
	}

	if err := h.service.ChangePassword(r.Context(), auth.ChangePasswordInput{
		UserID:          userID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}); err != nil {
		h.handleError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}
