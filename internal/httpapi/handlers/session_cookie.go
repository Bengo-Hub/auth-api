package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
)

// Cookie session for browser apps (fleet plan G11, owner decision 2026-11-17). The refresh token
// lives in a host-only HttpOnly cookie on the auth host, so page scripts never read it. The access
// token comes back in the body and the app keeps it in memory only.
//
// The bb_session cookie is a separate thing: it stays as it is for SSO on the login page and
// /authorize.
const (
	// SessionRefreshCookie holds the refresh token. The __Host- prefix makes the browser insist on
	// Secure, Path=/ and no Domain, so no other *.codevertexafrica.com host can set or read it.
	SessionRefreshCookie = "__Host-cv_refresh"
	// SessionCSRFHeader and SessionCSRFValue are the custom header every /session call carries.
	// A cross-origin request with it always needs a CORS preflight, which a foreign origin fails.
	SessionCSRFHeader = "X-Requested-With"
	SessionCSRFValue  = "codevertex"
)

// RequireSessionCSRF guards the cookie session routes. The request must carry
// X-Requested-With: codevertex and an Origin on the CORS allowlist; anything else is refused
// with 403 before a session is looked at. SameSite=Lax alone is not enough: every
// *.codevertexafrica.com host is the same site, webmail included. originAllowed is the CORS
// policy's own origin check; nil refuses every request.
func RequireSessionCSRF(originAllowed func(origin string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(SessionCSRFHeader) != SessionCSRFValue {
				writeError(w, http.StatusForbidden, "csrf_rejected", "missing or wrong "+SessionCSRFHeader+" header", nil)
				return
			}
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" || origin == "null" || originAllowed == nil || !originAllowed(origin) {
				writeError(w, http.StatusForbidden, "csrf_rejected", "origin not allowed", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SessionStart moves a session onto the cookie. The app posts the refresh token it got from the
// code exchange; one refresh proves it and rotates it, so the copy the page script saw stops
// working. The new refresh token goes only into the cookie.
func (h *AuthHandler) SessionStart(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required", nil)
		return
	}
	h.refreshIntoCookie(w, r, req.RefreshToken, req.ClientID)
}

// SessionRefresh trades the refresh cookie for a new access token. Rotation and the reuse rules
// are the service's (refresh_reuse.go), the same as POST /api/v1/auth/refresh.
func (h *AuthHandler) SessionRefresh(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(SessionRefreshCookie)
	if err != nil || c.Value == "" {
		writeError(w, http.StatusUnauthorized, "no_session", "no session cookie", nil)
		return
	}
	h.refreshIntoCookie(w, r, c.Value, "")
}

func (h *AuthHandler) refreshIntoCookie(w http.ResponseWriter, r *http.Request, refreshToken, clientID string) {
	result, err := h.service.Refresh(r.Context(), auth.RefreshInput{
		RefreshToken: refreshToken,
		ClientID:     clientID,
		IPAddress:    clientIP(r),
		UserAgent:    userAgent(r),
	})
	if err != nil {
		// The cookie is left alone on a failed refresh. Two tabs share one cookie: when one
		// rotates it, the other tab's call still in flight carries the old value and fails, and
		// clearing the cookie on that failure would wipe the token the first tab just set.
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid_session", "session expired or revoked; sign in again", nil)
			return
		}
		h.handleError(w, r, err)
		return
	}
	setSessionRefreshCookie(w, result.RefreshToken, result.RefreshTokenExpiresAt)
	writeJSON(w, http.StatusOK, h.toSessionResponse(result))
}

// SessionEnd signs the cookie session out: the session is revoked server-side and the cookie is
// cleared. A missing or already dead cookie still answers 200, so sign-out is idempotent. When the
// call also carries that session's access token, its jti is blocklisted as POST /auth/logout does.
func (h *AuthHandler) SessionEnd(w http.ResponseWriter, r *http.Request) {
	// Set before any body is written: a header added after WriteHeader is dropped.
	clearSessionRefreshCookie(w)

	c, err := r.Cookie(SessionRefreshCookie)
	if err != nil || c.Value == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}
	sessionID, err := h.service.SessionIDForRefreshToken(r.Context(), c.Value)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
			return
		}
		h.handleError(w, r, err)
		return
	}

	var jti string
	var ttl time.Duration
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims.SessionID == sessionID.String() {
		jti = claims.ID
		if claims.ExpiresAt != nil {
			if ttl = time.Until(claims.ExpiresAt.Time); ttl < 0 {
				ttl = 0
			}
		}
	}
	if err := h.service.Logout(r.Context(), sessionID, jti, ttl); err != nil {
		h.logger.Error("session end failed", zap.String("session_id", sessionID.String()), zap.Error(err))
		h.handleError(w, r, err)
		return
	}
	if h.redis != nil && h.redisNamespace != "" && sessionID != uuid.Nil {
		_ = h.redis.Del(r.Context(), h.redisNamespace+":session_token:"+sessionID.String()).Err()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// toSessionResponse is the login reply without the refresh token, which only travels in the
// cookie. session_id is left out as well: it is the bb_session cookie value, and the page has no
// use for it.
func (h *AuthHandler) toSessionResponse(result *auth.AuthResult) map[string]any {
	out := h.toAuthResponse(result)
	delete(out, "refresh_token")
	delete(out, "session_id")
	return out
}

func setSessionRefreshCookie(w http.ResponseWriter, value string, expires time.Time) {
	c := &http.Cookie{
		Name:     SessionRefreshCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if !expires.IsZero() {
		c.Expires = expires
		if c.MaxAge = int(time.Until(expires).Seconds()); c.MaxAge <= 0 {
			c.MaxAge = -1
		}
	}
	http.SetCookie(w, c)
}

func clearSessionRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionRefreshCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
