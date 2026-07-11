package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/oidc"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// platformTenantSlug is the slug of the platform/owner tenant. Members of this
// tenant are platform owners and may sign into ANY tenant — mirroring how the
// is_platform_owner claim grants cross-tenant access across the other services.
const platformTenantSlug = "codevertex"

// RolesPermissionsProvider returns roles and canonical permission codes for a user (for JWT claims).
type RolesPermissionsProvider interface {
	GetUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) (roles []string, permissions []string, err error)
}

// SubscriptionEnricher populates subscription claims (plan, status, features, limits)
// on a token input so OIDC-issued access tokens carry the same entitlements as the
// REST login/refresh flow. Implemented by auth.Service. Fail-open by contract.
type SubscriptionEnricher interface {
	EnrichAccessTokenInput(ctx context.Context, tenantID uuid.UUID, in *token.AccessTokenInput)
}

// OIDCHandler serves OIDC discovery and grant endpoints.
type OIDCHandler struct {
	cfg        *config.Config
	oidc       *oidc.Service
	auth       *authmiddleware.Auth
	tokenSvc    *token.Service
	rolesPerms  RolesPermissionsProvider // optional: for permissions in access token
	subEnricher SubscriptionEnricher     // optional: for subscription claims in access token
	logger      *zap.Logger
}

// NewOIDCHandler constructs a handler.
func NewOIDCHandler(cfg *config.Config, svc *oidc.Service, auth *authmiddleware.Auth, tokenSvc *token.Service, logger *zap.Logger) *OIDCHandler {
	return &OIDCHandler{
		cfg:      cfg,
		oidc:     svc,
		auth:     auth,
		tokenSvc: tokenSvc,
		logger:   logger,
	}
}

// NewOIDCHandlerWithRolesPermissions constructs a handler with optional provider for JWT permissions.
func NewOIDCHandlerWithRolesPermissions(cfg *config.Config, svc *oidc.Service, auth *authmiddleware.Auth, tokenSvc *token.Service, rolesPerms RolesPermissionsProvider, logger *zap.Logger) *OIDCHandler {
	h := &OIDCHandler{
		cfg:        cfg,
		oidc:       svc,
		auth:       auth,
		tokenSvc:   tokenSvc,
		rolesPerms: rolesPerms,
		logger:     logger,
	}
	// The provider passed in (auth.Service) also enriches subscription claims;
	// reuse it so OIDC-issued tokens carry entitlements like the REST flow.
	if enr, ok := rolesPerms.(SubscriptionEnricher); ok {
		h.subEnricher = enr
	}
	return h
}

// WellKnownConfig returns OIDC discovery document.
func (h *OIDCHandler) WellKnownConfig(w http.ResponseWriter, r *http.Request) {
	issuer := h.cfg.Token.Issuer
	j := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/api/v1/authorize",
		"token_endpoint":                        issuer + "/api/v1/token",
		"jwks_uri":                              issuer + "/api/v1/.well-known/jwks.json",
		"userinfo_endpoint":                     issuer + "/api/v1/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	writeJSON(w, http.StatusOK, j)
}

// JWKS returns JWKS set.
func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.tokenSvc.JWKS())
}

// Authorize implements the Authorization Code + PKCE flow.
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		// Unauthenticated: send the user to the Auth UI. A "sign-up" hint
		// (prompt=create or screen_hint=signup) routes new users to the signup
		// wizard instead of login; the originating service's full authorize URL
		// rides along as return_to so the flow lands back on its /auth/callback
		// (with the PKCE verifier it stored) after signup → login completes.
		dest := "/login"
		if hint := r.URL.Query().Get("prompt"); hint == "create" || hint == "signup" {
			dest = "/signup"
		}
		if hint := r.URL.Query().Get("screen_hint"); hint == "signup" || hint == "create" {
			dest = "/signup"
		}
		loginURL := h.cfg.App.AuthUIURL + dest

		// Preserve the original authorize request as return_to
		fullAuthorizeURL := h.cfg.Token.Issuer + r.URL.RequestURI()

		u, _ := url.Parse(loginURL)
		uq := u.Query()
		uq.Set("return_to", fullAuthorizeURL)

		// Propagate tenant slug if provided, else default to codevertex-demo
		tenant := r.URL.Query().Get("tenant")
		if tenant == "" {
			tenant = "codevertex-demo"
		}
		uq.Set("tenant", tenant)

		u.RawQuery = uq.Encode()

		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	if clientID == "" || redirectURI == "" || codeChallenge == "" || !strings.EqualFold(codeChallengeMethod, "S256") {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing or invalid parameters", nil)
		return
	}
	client, err := h.oidc.ClientByID(r.Context(), clientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client", "client not found", nil)
		return
	}
	if !h.oidc.ValidateRedirect(client, redirectURI) {
		writeError(w, http.StatusBadRequest, "invalid_redirect", "redirect not allowed", nil)
		return
	}
	// Validate that user is a member of the requested tenant.
	// Platform owners bypass this — they may authorize against any tenant.
	tenantFromURL := q.Get("tenant")
	if tenantFromURL != "" && !claims.IsPlatformOwner {
		userID := parseUUID(claims.Subject)
		memberships, err := h.oidc.GetUserMemberships(r.Context(), userID)
		if err != nil {
			reqID := middleware.GetReqID(r.Context())
			h.logger.Error("failed to fetch user memberships", zap.String("request_id", reqID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to verify tenant membership", map[string]any{"request_id": reqID})
			return
		}
		isMember := false
		for _, m := range memberships {
			if m.TenantSlug == tenantFromURL {
				isMember = true
				break
			}
		}
		if !isMember {
			h.logger.Warn("user not a member of requested tenant",
				zap.String("user_id", claims.Subject),
				zap.String("tenant", tenantFromURL))
			// Redirect back with error so the client can handle it
			if redirectURI != "" {
				u, _ := url.Parse(redirectURI)
				params := u.Query()
				params.Set("error", "access_denied")
				params.Set("error_description", "You are not a member of the requested tenant")
				if state != "" {
					params.Set("state", state)
				}
				u.RawQuery = params.Encode()
				http.Redirect(w, r, u.String(), http.StatusFound)
				return
			}
			writeError(w, http.StatusForbidden, "access_denied", "You are not a member of the requested tenant", nil)
			return
		}
	}

	// Generate code (include tenant from authorize URL so token exchange can prefer it)
	codePlain := randomOIDCString(32)
	_, err = h.oidc.CreateAuthorizationCode(
		r.Context(),
		parseUUID(claims.Subject),
		clientID,
		redirectURI,
		scope,
		nonce,
		codePlain,
		codeChallenge,
		codeChallengeMethod,
		tenantFromURL,
	)
	if err != nil {
		reqID := middleware.GetReqID(r.Context())
		h.logger.Error("create auth code failed", zap.String("request_id", reqID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create code", map[string]any{"request_id": reqID})
		return
	}
	// Redirect back with code and state
	u, _ := url.Parse(redirectURI)
	params := u.Query()
	params.Set("code", codePlain)
	if state != "" {
		params.Set("state", state)
	}
	u.RawQuery = params.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// Token exchanges authorization codes for token pairs.
func (h *OIDCHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid form", nil)
		return
	}
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")
	if code == "" || redirectURI == "" || clientID == "" || codeVerifier == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing parameters", nil)
		return
	}

	userEntity, client, authCode, err := h.oidc.ExchangeCode(r.Context(), code, clientID, redirectURI, codeVerifier)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
		return
	}

	scopes := scopesFromString(authCode.Scope)

	// Fetch user memberships for enriched tokens
	memberships, _ := h.oidc.GetUserMemberships(r.Context(), userEntity.ID)
	var roles []string
	var tenantID *uuid.UUID
	var tenantSlug string
	// Platform owners (members of the platform tenant) may obtain a token scoped to
	// ANY tenant — the same cross-tenant access the is_platform_owner claim grants in
	// pos-api / treasury / inventory.
	isPlatformOwner := false
	for _, m := range memberships {
		if m.TenantSlug == platformTenantSlug {
			isPlatformOwner = true
			break
		}
	}
	// Collect all roles and resolve requested tenant
	requestedSlug, _ := authCode.Metadata["tenant_slug"].(string)
	for _, m := range memberships {
		roles = append(roles, m.Roles...)
		if requestedSlug != "" && m.TenantSlug == requestedSlug {
			tid := m.TenantID
			tenantID = &tid
			tenantSlug = m.TenantSlug
		}
	}
	// Platform owner signing into a tenant they are not a member of: resolve that
	// tenant directly so the token is scoped to it (e.g. cross-tenant POS support).
	if requestedSlug != "" && tenantID == nil && isPlatformOwner {
		if t, err := h.oidc.TenantBySlug(r.Context(), requestedSlug); err == nil && t != nil {
			tid := t.ID
			tenantID = &tid
			tenantSlug = t.Slug
		} else {
			h.logger.Warn("platform owner requested unknown tenant",
				zap.String("user_id", userEntity.ID.String()),
				zap.String("requested_tenant", requestedSlug),
				zap.Error(err))
		}
	}
	// If a specific tenant was requested but the user is neither a member nor a
	// platform owner (or the tenant doesn't exist), reject the token exchange.
	if requestedSlug != "" && tenantID == nil {
		h.logger.Warn("token exchange denied: user not a member of requested tenant",
			zap.String("user_id", userEntity.ID.String()),
			zap.String("requested_tenant", requestedSlug))
		writeError(w, http.StatusForbidden, "access_denied", "user is not a member of the requested tenant", nil)
		return
	}
	// Fallback: first or primary membership when no specific tenant was requested
	if tenantID == nil {
		for _, m := range memberships {
			if tenantID == nil || (userEntity.PrimaryTenantID != "" && m.TenantID.String() == userEntity.PrimaryTenantID) {
				tid := m.TenantID
				tenantID = &tid
				tenantSlug = m.TenantSlug
			}
		}
	}

	// Create session when offline_access is requested (enables refresh tokens)
	var sessionID uuid.UUID
	var refreshToken string
	if hasScope(scopes, "offline_access") {
		session, sessErr := h.oidc.CreateSession(r.Context(), userEntity.ID, clientID, r.RemoteAddr, r.UserAgent())
		if sessErr != nil {
			h.logger.Error("create oidc session failed", zap.Error(sessErr))
			writeError(w, http.StatusInternalServerError, "server_error", "session creation failed", nil)
			return
		}
		sessionID = session.SessionID
		refreshToken = session.RefreshToken
	} else {
		sessionID = uuid.New()
	}

	var permissions []string
	if h.rolesPerms != nil {
		_, permissions, _ = h.rolesPerms.GetUserRolesAndPermissions(r.Context(), userEntity.ID)
	}

	// Mint access token with roles, permissions, and tenant info
	tokenInput := token.AccessTokenInput{
		UserID:          userEntity.ID,
		TenantID:        tenantID,
		TenantSlug:      tenantSlug,
		SessionID:       sessionID,
		Email:           userEntity.Email,
		Scopes:          scopes,
		Roles:           roles,
		Permissions:     permissions,
		IsPlatformOwner: isPlatformOwner,
		IsDemo:          tenantSlug == "codevertex-demo",
		Audience:        []string{client.ClientID, h.cfg.Token.Audience},
	}
	// Enrich with subscription claims so OIDC-issued tokens gate features identically
	// to the REST login/refresh flow (fail-open). Without this, services that read
	// SubscriptionFeatures from the JWT (e.g. inventory-api RequireFeature) reject
	// entitled tenants with feature_not_available.
	if tenantID != nil && h.subEnricher != nil {
		h.subEnricher.EnrichAccessTokenInput(r.Context(), *tenantID, &tokenInput)
	}
	access, accessExp, err := h.tokenSvc.MintAccessToken(tokenInput)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "mint access token failed", nil)
		return
	}

	// Build enriched ID token
	now := time.Now().UTC()
	idClaims := map[string]any{
		"iss":            h.cfg.Token.Issuer,
		"aud":            client.ClientID,
		"sub":            userEntity.ID.String(),
		"email":          userEntity.Email,
		"email_verified": userEntity.EmailVerified,
		"nonce":          authCode.Nonce,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"name":           firstProfileString(userEntity.Profile, "name"),
		"phone":          firstProfileString(userEntity.Profile, "phone"),
		"roles":          roles,
	}
	if tenantID != nil {
		idClaims["tenant_id"] = tenantID.String()
		idClaims["tenant_slug"] = tenantSlug
	}
	if len(memberships) > 0 {
		tenants := make([]map[string]any, 0, len(memberships))
		for _, m := range memberships {
			tenants = append(tenants, map[string]any{
				"id":    m.TenantID.String(),
				"slug":  m.TenantSlug,
				"name":  m.TenantName,
				"roles": m.Roles,
			})
		}
		idClaims["tenants"] = tenants
	}

	idToken, err := h.tokenSvc.SignJWT(idClaims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "mint id token failed", nil)
		return
	}

	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessExp).Seconds()),
		"id_token":     idToken,
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	writeJSON(w, http.StatusOK, resp)
}

// UserInfo returns standard OIDC claims for the current user, including tenant and role data.
func (h *OIDCHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	userID := parseUUID(claims.Subject)
	u, err := h.oidc.GetUserByID(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "user not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, h.oidc.UserInfoPayloadFull(r.Context(), u))
}

// helpers

func scopesFromString(s string) []string {
	var out []string
	for _, p := range strings.Fields(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}

func firstProfileString(profile map[string]any, key string) string {
	if profile == nil {
		return ""
	}
	if v, ok := profile[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func randomOIDCString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseUUID(s string) uuid.UUID {
	id, _ := uuid.Parse(s)
	return id
}
