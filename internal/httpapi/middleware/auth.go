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

// Auth provides JWT-backed authentication middleware.
type Auth struct {
	validator TokenValidator
	revoked   RevocationChecker
}

// NewAuth creates a new instance.
func NewAuth(validator TokenValidator, revoked RevocationChecker) *Auth {
	return &Auth{validator: validator, revoked: revoked}
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
			claims, err := a.validator.ValidateAccessToken(cookie.Value)
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
			claims, err := a.validator.ValidateAccessToken(cookie.Value)
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

		next.ServeHTTP(w, r)
	})
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
