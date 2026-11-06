package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bengobox/auth-api/internal/token"
)

// staticValidator accepts the one token string it knows.
type staticValidator struct{ claims *token.Claims }

func (v staticValidator) ValidateAccessToken(s string) (*token.Claims, error) {
	if s != "good" {
		return nil, errors.New("bad token")
	}
	return v.claims, nil
}

func serve(mw func(http.Handler) http.Handler, method, path string) (status int, sawClaims bool) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	return rec.Code, sawClaims
}

// An enrolment-only token reaches the profile, the authenticator setup and sign-out, and nothing
// else: RequireAuth refuses it with mfa_enrollment_required, and TryAuth (the authorize endpoint)
// treats the caller as signed out.
func TestEnrollmentOnlyTokenAllowlist(t *testing.T) {
	enrolling := NewAuth(staticValidator{&token.Claims{MFAEnrollmentRequired: true}}, nil)
	normal := NewAuth(staticValidator{&token.Claims{}}, nil)

	allowed := [][2]string{
		{http.MethodGet, "/api/v1/auth/me"},
		{http.MethodGet, "/api/v1/auth/me/"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodPost, "/api/v1/auth/mfa/totp/start"},
		{http.MethodPost, "/api/v1/auth/mfa/totp/confirm"},
		{http.MethodPost, "/api/v1/auth/mfa/backup-codes/regenerate"},
	}
	refused := [][2]string{
		{http.MethodPatch, "/api/v1/auth/me"},
		{http.MethodGet, "/api/v1/auth/me/memberships"},
		{http.MethodPost, "/api/v1/auth/me/change-password"},
		{http.MethodGet, "/api/v1/admin/tenants"},
		{http.MethodGet, "/api/v1/userinfo"},
		{http.MethodGet, "/api/v1/auth/sessions"},
		{http.MethodPost, "/api/v1/auth/mfa/backup-codes/consume"},
	}
	for _, rt := range allowed {
		if code, saw := serve(enrolling.RequireAuth, rt[0], rt[1]); code != http.StatusNoContent || !saw {
			t.Errorf("%s %s: %d, want allowed", rt[0], rt[1], code)
		}
	}
	for _, rt := range refused {
		if code, _ := serve(enrolling.RequireAuth, rt[0], rt[1]); code != http.StatusForbidden {
			t.Errorf("%s %s: %d, want 403", rt[0], rt[1], code)
		}
		if code, _ := serve(normal.RequireAuth, rt[0], rt[1]); code != http.StatusNoContent {
			t.Errorf("normal token on %s %s: %d", rt[0], rt[1], code)
		}
	}
	if code, saw := serve(enrolling.TryAuth, http.MethodGet, "/api/v1/authorize"); code != http.StatusNoContent || saw {
		t.Errorf("authorize with an enrolment-only token: %d claims=%v, want anonymous", code, saw)
	}
	if _, saw := serve(normal.TryAuth, http.MethodGet, "/api/v1/authorize"); !saw {
		t.Error("authorize with a normal token lost its claims")
	}
}
