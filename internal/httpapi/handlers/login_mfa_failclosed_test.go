package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/services/auth"
)

// loginMFAFake answers a correct password and a configurable MFA lookup.
type loginMFAFake struct {
	AuthService
	mfaOn  bool
	mfaErr error
}

func (f *loginMFAFake) Login(context.Context, auth.LoginInput) (*auth.AuthResult, error) {
	return &auth.AuthResult{User: &ent.User{ID: uuid.New()}, AccessToken: "access", RefreshToken: "refresh"}, nil
}

func (f *loginMFAFake) IsMFAEnabled(context.Context, uuid.UUID) (bool, error) {
	return f.mfaOn, f.mfaErr
}

// A failed MFA lookup must never let a password alone through: the answer asks for the code and
// carries no token, the same fail-closed rule the phone and social paths follow.
func TestLoginFailsClosedWhenTheMFALookupFails(t *testing.T) {
	cases := map[string]*loginMFAFake{
		"lookup error":    {mfaErr: errors.New("database unavailable")},
		"mfa on, no code": {mfaOn: true},
	}
	for name, svc := range cases {
		t.Run(name, func(t *testing.T) {
			h := &AuthHandler{service: svc, logger: zap.NewNop()}
			rec := phoneOTPPost(h.Login, `{"email":"staff@example.com","password":"correct horse"}`)
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, `"mfa_required":true`) {
				t.Fatalf("%s: %d %s, want mfa_required", name, rec.Code, body)
			}
			if strings.Contains(body, "access") || strings.Contains(body, "refresh") {
				t.Fatalf("%s: a token leaked: %s", name, body)
			}
		})
	}
}
