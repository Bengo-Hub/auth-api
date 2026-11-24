package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/services/auth"
)

// The callback sends a finished or failed link back to Account settings, never to the sign-in page,
// and never sets a session cookie for it. A failed sign-in names the provider for the login hint.
func TestOAuthCallbackLinkRedirects(t *testing.T) {
	h := &AuthHandler{logger: zap.NewNop()}
	cases := []struct {
		name     string
		result   *auth.AuthResult
		err      error
		wantPath string
		wantQS   string
	}{
		{"linked", &auth.AuthResult{LinkedProvider: "google"}, nil, signInMethodsPath, "linked=google"},
		{"link conflict", nil, &auth.SocialLinkError{Provider: "google", Err: auth.ErrSocialIdentityLinkedElsewhere}, signInMethodsPath, "link_error="},
		{"sign-in refused", nil, auth.ErrTenantMembershipRequired, "/login?", "oauth_provider=google"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/google/callback?code=c&state=s", nil)
			w := httptest.NewRecorder()
			h.handleOAuthCallback(w, r, "google", func(context.Context, auth.OAuthCallbackInput) (*auth.AuthResult, error) {
				return c.result, c.err
			})
			loc := w.Header().Get("Location")
			if w.Code != http.StatusFound || !strings.Contains(loc, c.wantPath) || !strings.Contains(loc, c.wantQS) {
				t.Fatalf("status %d location %q", w.Code, loc)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("no session cookie may be set")
			}
		})
	}
}
