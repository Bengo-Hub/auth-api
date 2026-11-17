package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	entapp "github.com/bengobox/auth-api/internal/ent/app"
	"github.com/bengobox/auth-api/internal/ent/tenant"
)

// GrantClientCredentials is the OAuth2 grant (RFC 6749 section 4.4) a developer App uses to
// trade its consumer key (client_id) and consumer secret for a short-lived access token.
const GrantClientCredentials = "client_credentials"

// TokenUseClientCredentials is stamped in the token_use claim of every client_credentials
// token so a consumer can tell a machine token from a user session without guessing.
const TokenUseClientCredentials = "client_credentials"

// SetAppStore enables the client_credentials grant on the token endpoint. Without it the
// grant answers unsupported_grant_type.
func (h *OIDCHandler) SetAppStore(entClient *ent.Client) { h.apps = entClient }

// oauthError writes an RFC 6749 section 5.2 error body.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="codevertex", error="`+code+`"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// clientCredentialsToken handles grant_type=client_credentials. The form must already be
// parsed. Credentials come from HTTP Basic auth (client_secret_basic) or the client_id and
// client_secret form fields (client_secret_post).
//
// The minted token's only audience is ClientCredentialsAudience, so services that accept user
// sessions refuse it, and it carries no roles or permissions. Its authority is exactly the
// app's scopes (or the subset asked for), its tenant and its environment.
func (h *OIDCHandler) clientCredentialsToken(w http.ResponseWriter, r *http.Request) {
	if h.apps == nil {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "client_credentials is not enabled")
		return
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	secret := r.FormValue("client_secret")
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		clientID, secret = strings.TrimSpace(basicID), basicSecret
	}
	if clientID == "" || secret == "" {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client_id and client_secret are required")
		return
	}

	ctx := r.Context()
	a, err := h.apps.App.Query().Where(entapp.ClientIDEQ(clientID)).Only(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			h.logger.Error("client_credentials: app lookup", zap.Error(err))
			oauthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
			return
		}
		// Hash anyway so an unknown client_id costs the same as a wrong secret.
		_ = hashAPIKey(secret)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	if !secretMatches(a.ClientSecretHash, secret) {
		h.logger.Warn("client_credentials: bad secret", zap.String("client_id", clientID))
		oauthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	if a.AppType != entapp.AppTypeTenant || a.TenantID == nil {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "only tenant apps can use client_credentials")
		return
	}
	if a.Status != entapp.StatusActive {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "app is "+string(a.Status))
		return
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.IsZero() && time.Now().After(*a.ExpiresAt) {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "app credentials have expired")
		return
	}
	// The developer calls this endpoint directly, so this is their real address.
	ip := getClientIP(r)
	if !ipAllowed(a.AllowedIps, ip) {
		oauthError(w, http.StatusForbidden, "access_denied", "request IP is not on the app's allowlist")
		return
	}
	scopes, ok := grantedScopes(a.Scopes, r.FormValue("scope"))
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds the app's scopes")
		return
	}

	tenantSlug := ""
	if t, terr := h.apps.Tenant.Query().Where(tenant.IDEQ(*a.TenantID)).Only(ctx); terr == nil {
		tenantSlug = t.Slug
	}

	ttl := h.cfg.Token.ClientCredentialsTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()
	exp := now.Add(ttl)
	signed, err := h.tokenSvc.SignJWT(map[string]any{
		"iss":         h.cfg.Token.Issuer,
		"aud":         []string{h.cfg.Token.ClientCredentialsAudience},
		"sub":         a.ClientID,
		"client_id":   a.ClientID,
		"azp":         a.ClientID,
		"tenant_id":   a.TenantID.String(),
		"tenant_slug": tenantSlug,
		"scope":       strings.Join(scopes, " "),
		"scopes":      scopes,
		"env":         string(a.Environment),
		"token_use":   TokenUseClientCredentials,
		"jti":         uuid.NewString(),
		"iat":         now.Unix(),
		"nbf":         now.Unix(),
		"exp":         exp.Unix(),
	})
	if err != nil {
		h.logger.Error("client_credentials: sign", zap.Error(err))
		oauthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	appID := a.ID
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = h.apps.App.UpdateOneID(appID).SetLastUsedAt(time.Now()).SetLastUsedIP(ip).Save(bg)
	}()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": signed,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
		"scope":        strings.Join(scopes, " "),
	})
}

// secretMatches compares a presented consumer secret against the stored hash in constant time.
func secretMatches(stored *string, presented string) bool {
	if stored == nil || *stored == "" {
		_ = hashAPIKey(presented)
		return false
	}
	return subtle.ConstantTimeCompare([]byte(*stored), []byte(hashAPIKey(presented))) == 1
}

// ipAllowed reports whether ip may use an app with this allowlist. An empty list allows all.
func ipAllowed(allowlist []string, ip string) bool {
	if len(allowlist) == 0 {
		return true
	}
	for _, a := range allowlist {
		if a == "*" || a == ip {
			return true
		}
	}
	return false
}

// grantedScopes resolves the space-separated scope parameter against the app's scopes. An
// empty request grants all of them; any scope the app lacks fails the whole request, as RFC
// 6749 section 3.3 allows, rather than silently narrowing it.
func grantedScopes(appScopes []string, requested string) ([]string, bool) {
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		out := make([]string, len(appScopes))
		copy(out, appScopes)
		return out, true
	}
	have := make(map[string]bool, len(appScopes))
	for _, s := range appScopes {
		have[s] = true
	}
	seen := make(map[string]bool, len(fields))
	out := make([]string, 0, len(fields))
	for _, s := range fields {
		if !have[s] {
			return nil, false
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, true
}
