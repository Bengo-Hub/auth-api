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
			if err == nil {
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
				if err == nil {
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

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": message,
		"code":  "unauthorized",
	})
}

type claimsContextKey struct{}

// ClaimsFromContext extracts token claims stored by middleware.
func ClaimsFromContext(ctx context.Context) (*token.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*token.Claims)
	return claims, ok && claims != nil
}
