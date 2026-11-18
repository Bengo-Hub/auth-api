package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/services/auth"
)

const testAccountsOrigin = "https://accounts.codevertexafrica.com"

type loginOKFake struct{ AuthService }

func (loginOKFake) Login(context.Context, auth.LoginInput) (*auth.AuthResult, error) {
	return &auth.AuthResult{
		User:                  &ent.User{ID: uuid.New(), Email: "staff@example.com"},
		AccessToken:           "access-1", // secret-scan:allow fake fixture
		AccessTokenExpiresAt:  time.Now().Add(15 * time.Minute),
		RefreshToken:          "rt-secret",
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		SessionID:             uuid.New(),
	}, nil
}

// The accounts UI keeps its session in cookies, so its password sign-in reply leaves out
// refresh_token and session_id; any other origin (in-app passkey hand-off, custom domains,
// terminals, no Origin at all) still gets them.
func TestLoginBodyTokensByOrigin(t *testing.T) {
	cases := []struct {
		origin    string
		wantToken bool
	}{
		{testAccountsOrigin, false},
		{testAccountsOrigin + "/", false},
		{"HTTPS://ACCOUNTS.codevertexafrica.com", false},
		{testAppOrigin, true},
		{"https://accounts.codevertexafrica.com.evil.example", true},
		{"", true},
	}
	for _, c := range cases {
		t.Run(c.origin, func(t *testing.T) {
			h := &AuthHandler{service: loginOKFake{}, logger: zap.NewNop()}
			h.SetCookieOnlyOrigins([]string{testAccountsOrigin})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
				strings.NewReader(`{"email":"staff@example.com","password":"correct horse"}`))
			req.Header.Set("Content-Type", "application/json")
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			rec := httptest.NewRecorder()
			h.Login(rec, req)
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, `"access_token":"access-1"`) { // secret-scan:allow fake fixture
				t.Fatalf("%d %s", rec.Code, body)
			}
			hasRT := strings.Contains(body, "rt-secret")
			hasSID := strings.Contains(body, `"session_id"`)
			if hasRT != c.wantToken || hasSID != c.wantToken {
				t.Fatalf("origin %q: refresh_token present %v, session_id present %v, want %v: %s",
					c.origin, hasRT, hasSID, c.wantToken, body)
			}
		})
	}
}
