package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/services/auth"
)

// loginMFAFake answers Login the way the service does once the password is right: the error it
// is given, and records the code it was sent.
type loginMFAFake struct {
	AuthService
	err      error
	gotTOTP  string
	loginHit bool
}

func (f *loginMFAFake) Login(_ context.Context, in auth.LoginInput) (*auth.AuthResult, error) {
	f.loginHit = true
	f.gotTOTP = in.TOTPCode
	return nil, f.err
}

// The service checks the authenticator code before any session exists (and fails closed when the
// lookup errors, see TestPasswordLoginMFA). The handler turns its answers into the responses the
// sign-in form knows, and a refusal never carries a token.
func TestLoginMapsTheServiceMFAAnswers(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		body     string
		status   int
		contains string
	}{
		{"code owed", &auth.MFARequiredError{UserID: uuid.New()}, `{"email":"staff@example.com","password":"correct horse"}`, http.StatusOK, `"mfa_required":true`},
		{"wrong code", auth.ErrMFACodeInvalid, `{"email":"staff@example.com","password":"correct horse","totp_code":"000000"}`, http.StatusUnauthorized, `"invalid_totp"`},
		{"covered session without the code", auth.ErrMFARequired, `{"email":"staff@example.com","password":"correct horse"}`, http.StatusUnauthorized, `"mfa_required"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := &loginMFAFake{err: c.err}
			h := &AuthHandler{service: svc, logger: zap.NewNop()}
			rec := phoneOTPPost(h.Login, c.body)
			body := rec.Body.String()
			if rec.Code != c.status || !strings.Contains(body, c.contains) {
				t.Fatalf("%d %s, want %d with %s", rec.Code, body, c.status, c.contains)
			}
			if strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
				t.Fatalf("a token leaked: %s", body)
			}
		})
	}
}

// The code typed on the second submit reaches the service, trimmed.
func TestLoginPassesTheCodeToTheService(t *testing.T) {
	svc := &loginMFAFake{err: auth.ErrMFACodeInvalid}
	h := &AuthHandler{service: svc, logger: zap.NewNop()}
	phoneOTPPost(h.Login, `{"email":"staff@example.com","password":"correct horse","totp_code":" 123456 "}`)
	if !svc.loginHit || svc.gotTOTP != "123456" {
		t.Fatalf("service got %q (called %v), want 123456", svc.gotTOTP, svc.loginHit)
	}
}
