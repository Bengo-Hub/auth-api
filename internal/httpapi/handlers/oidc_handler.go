package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bengobox/auth-service/internal/config"
	authmiddleware "github.com/bengobox/auth-service/internal/httpapi/middleware"
	"github.com/bengobox/auth-service/internal/services/oidc"
	"github.com/bengobox/auth-service/internal/token"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// OIDCHandler serves OIDC discovery and grant endpoints.
type OIDCHandler struct {
	cfg      *config.Config
	oidc     *oidc.Service
	auth     *authmiddleware.Auth
	tokenSvc *token.Service
	logger   *zap.Logger
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

// WellKnownConfig returns OIDC discovery document.
func (h *OIDCHandler) WellKnownConfig(w http.ResponseWriter, r *http.Request) {
	issuer := h.cfg.Token.Issuer
	j := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"userinfo_endpoint":                     issuer + "/userinfo",
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
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
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
	// Generate code
	codePlain := randomString(32)
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
	// Use access-token service to mint tokens
	access, accessExp, err := h.tokenSvc.MintAccessToken(token.AccessTokenInput{
		UserID:    userEntity.ID,
		TenantID:  nil,
		SessionID: uuid.New(),
		Email:     userEntity.Email,
		Scopes:    scopesFromString(authCode.Scope),
		Audience:  []string{client.ClientID},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "mint access token failed", nil)
		return
	}
	// Build ID token
	idClaims := map[string]any{
		"iss":            h.cfg.Token.Issuer,
		"aud":            client.ClientID,
		"sub":            userEntity.ID.String(),
		"email":          userEntity.Email,
		"email_verified": true,
		"nonce":          authCode.Nonce,
		"iat":            time.Now().UTC().Unix(),
		"exp":            time.Now().UTC().Add(5 * time.Minute).Unix(),
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
	writeJSON(w, http.StatusOK, resp)
}

// UserInfo returns standard OIDC claims for the current user.
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
	writeJSON(w, http.StatusOK, h.oidc.UserInfoPayload(u))
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

func randomString(n int) string {
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

// mintIDToken creates a minimal OIDC ID token.
// signing moved to token service; no local signer here
