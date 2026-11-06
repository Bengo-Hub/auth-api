package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/bengobox/auth-api/internal/token"
)

// TokenValidator defines the capabilities required to validate JWTs.
type TokenValidator interface {
	ValidateAccessToken(tokenStr string) (*token.Claims, error)
}

// RevocationChecker checks if a jti is revoked.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// SessionResolver resolves a session reference (e.g. UUID) to a JWT.
// Used when the bb_session cookie contains a session ID rather than the full
// JWT (admin tokens can be >4KB which exceeds browser cookie limits).
type SessionResolver interface {
	ResolveSessionToken(ctx context.Context, sessionRef string) (string, error)
}

// Auth provides JWT-backed authentication middleware.
type Auth struct {
	validator TokenValidator
	revoked   RevocationChecker
	sessions  SessionResolver // optional; nil means cookie must contain a JWT directly
}

// NewAuth creates a new instance.
func NewAuth(validator TokenValidator, revoked RevocationChecker) *Auth {
	return &Auth{validator: validator, revoked: revoked}
}

// SetSessionResolver configures the session resolver for opaque session cookies.
func (a *Auth) SetSessionResolver(sr SessionResolver) {
	a.sessions = sr
}

// RequireAuth ensures incoming requests possess a valid bearer token.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			tokenStr := strings.TrimSpace(authHeader[7:])
			claims, err := a.validator.ValidateAccessToken(tokenStr)
			if err == nil {
				if a.revoked != nil && claims != nil && claims.ID != "" {
					if revoked, err := a.revoked.IsRevoked(r.Context(), claims.ID); err == nil && revoked {
						writeAuthError(w, http.StatusUnauthorized, "token revoked")
						return
					}
				}
				if claims.IsEquityPortalOnly() {
					writeAuthErrorCode(w, http.StatusForbidden, "invalid_token_scope", equityPortalScopeRejection)
					return
				}
				if !EnrollmentRouteAllowed(claims, r) {
					writeAuthErrorCode(w, http.StatusForbidden, "mfa_enrollment_required", mfaEnrollmentRejection)
					return
				}
				ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// 2. Check session cookie
		cookie, err := r.Cookie("bb_session")
		if err == nil {
			tokenStr := a.resolveSessionCookie(r.Context(), cookie.Value)
			if tokenStr != "" {
				claims, err := a.validator.ValidateAccessToken(tokenStr)
				if err == nil {
					if a.revoked != nil && claims != nil && claims.ID != "" {
						if revoked, err := a.revoked.IsRevoked(r.Context(), claims.ID); err == nil && revoked {
							writeAuthError(w, http.StatusUnauthorized, "token revoked")
							return
						}
					}
					if claims.IsEquityPortalOnly() {
						writeAuthErrorCode(w, http.StatusForbidden, "invalid_token_scope", equityPortalScopeRejection)
						return
					}
					if !EnrollmentRouteAllowed(claims, r) {
						writeAuthErrorCode(w, http.StatusForbidden, "mfa_enrollment_required", mfaEnrollmentRejection)
						return
					}
					ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		writeAuthError(w, http.StatusUnauthorized, "missing or invalid auth")
	})
}

// TryAuth attempts to populate the context with claims if a valid token or cookie is present,
// but does not fail the request if auth is missing or invalid.
func (a *Auth) TryAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			tokenStr := strings.TrimSpace(authHeader[7:])
			claims, err := a.validator.ValidateAccessToken(tokenStr)
			// Portal-only tokens are never a session, and an enrolment-only token is one only on the
			// setup routes: elsewhere (the authorize endpoint above all) the context stays anonymous.
			if err == nil && !claims.IsEquityPortalOnly() && EnrollmentRouteAllowed(claims, r) {
				if a.revoked != nil && claims != nil && claims.ID != "" {
					if revoked, err := a.revoked.IsRevoked(r.Context(), claims.ID); err == nil && !revoked {
						ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				} else {
					ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		// 2. Check session cookie
		cookie, err := r.Cookie("bb_session")
		if err == nil {
			tokenStr := a.resolveSessionCookie(r.Context(), cookie.Value)
			if tokenStr != "" {
				claims, err := a.validator.ValidateAccessToken(tokenStr)
				// Portal-only tokens are never a session, and enrolment-only tokens only on the setup
				// routes: leave the context anonymous otherwise.
				if err == nil && !claims.IsEquityPortalOnly() && EnrollmentRouteAllowed(claims, r) {
					if a.revoked != nil && claims != nil && claims.ID != "" {
						if revoked, err := a.revoked.IsRevoked(r.Context(), claims.ID); err == nil && !revoked {
							ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						}
					} else {
						ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// resolveSessionCookie returns a JWT token string from a cookie value.
// If the value looks like a JWT (contains dots), it is returned as-is.
// Otherwise it is treated as a session reference (UUID) and resolved via Redis.
func (a *Auth) resolveSessionCookie(ctx context.Context, value string) string {
	if strings.Contains(value, ".") {
		// Looks like a JWT — use directly (backwards compat with old cookies)
		return value
	}
	// Opaque session reference — resolve from Redis
	if a.sessions != nil {
		if tok, err := a.sessions.ResolveSessionToken(ctx, value); err == nil && tok != "" {
			return tok
		}
	}
	return ""
}

// equityPortalScopeRejection is returned when an equity-holder portal link token
// is presented on a normal session route. The portal token is minted for a bare
// holder UUID with no login, so honouring it here would turn a shareable link
// into a full platform session.
const equityPortalScopeRejection = "equity portal tokens are only valid on equity portal routes"

// mfaEnrollmentRejection is returned when an enrolment-only token is used outside the setup routes.
const mfaEnrollmentRejection = "set up an authenticator app, then sign in again"

// enrollmentRoutes are the only routes an enrolment-only token reaches: the profile (so the UI
// knows to show the setup), the authenticator setup and its backup codes, and sign-out.
var enrollmentRoutes = routeSet(
	"GET /api/v1/auth/me",
	"POST /api/v1/auth/logout",
	"POST /api/v1/auth/mfa/totp/start",
	"POST /api/v1/auth/mfa/totp/confirm",
	"POST /api/v1/auth/mfa/backup-codes/regenerate",
)

func routeSet(routes ...string) map[string]bool {
	set := make(map[string]bool, len(routes))
	for _, r := range routes {
		set[r] = true
	}
	return set
}

// EnrollmentRouteAllowed reports whether claims may be used on this request. Every token passes
// except an enrolment-only one (token.Claims.MFAEnrollmentRequired) off the setup routes.
func EnrollmentRouteAllowed(claims *token.Claims, r *http.Request) bool {
	if claims == nil || !claims.MFAEnrollmentRequired {
		return true
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	return enrollmentRoutes[r.Method+" "+path]
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	writeAuthErrorCode(w, status, "unauthorized", message)
}

func writeAuthErrorCode(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": message,
		"code":  code,
	})
}

type claimsContextKey struct{}

// ClaimsFromContext extracts token claims stored by middleware.
func ClaimsFromContext(ctx context.Context) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*token.Claims)
	return claims, ok && claims != nil
}

// ContextWithClaims returns a child context carrying the given claims. Used by
// internal-key S2S routes to present a platform-trust identity to admin handlers
// that authorize via ClaimsFromContext (e.g. requireTenantAdmin). The INTERNAL_SERVICE_KEY
// already establishes platform-level trust, so synthesizing platform-owner claims here
// is semantically equivalent to a platform-owner JWT.
func ContextWithClaims(ctx context.Context, claims *token.Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}
