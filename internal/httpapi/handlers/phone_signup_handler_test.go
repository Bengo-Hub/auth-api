package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/services/auth"
)

// phoneSignupFakeService answers the phone code calls: tenant "open" admits unknown phones
// (phone self-signup on), tenant "closed" refuses them like any miss.
type phoneSignupFakeService struct {
	AuthService
	sent   []*auth.PhoneLoginTarget
	logins []*auth.PhoneLoginTarget
}

func (f *phoneSignupFakeService) FindPhoneLoginTarget(_ context.Context, slug, phone string) (*auth.PhoneLoginTarget, error) {
	if slug != "open" {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.PhoneLoginTarget{Tenant: &ent.Tenant{ID: uuid.New(), Slug: slug}, Phone: phone,
		Signup: &auth.PhoneSignupPolicy{Role: "customer", Services: []string{"hadia"}}}, nil
}

func (f *phoneSignupFakeService) SendPhoneOTP(_ context.Context, t *auth.PhoneLoginTarget, _ string, _ time.Duration, _ string) {
	f.sent = append(f.sent, t)
}

func (f *phoneSignupFakeService) LoginWithPhoneOTP(_ context.Context, t *auth.PhoneLoginTarget, _, _, _ string) (*auth.AuthResult, error) {
	f.logins = append(f.logins, t)
	return &auth.AuthResult{User: &ent.User{ID: uuid.New()}, Tenant: t.Tenant, AccessToken: "access", RefreshToken: "refresh",
		AccessTokenExpiresAt: time.Now().Add(time.Hour), RefreshTokenExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (f *phoneSignupFakeService) IsMFAEnabled(context.Context, uuid.UUID) (bool, error) {
	panic("a phone that signs up has no account to check for MFA")
}

func phoneOTPPost(h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return rec
}

func TestPhoneSelfSignupHandlers(t *testing.T) {
	mr := miniredis.RunT(t)
	svc := &phoneSignupFakeService{}
	h := &AuthHandler{service: svc, logger: zap.NewNop(), redis: redis.NewClient(&redis.Options{Addr: mr.Addr()}), redisNamespace: "test"}

	open := phoneOTPPost(h.RequestPhoneOTP, `{"tenant_slug":"open","phone":"+254711000001"}`)
	closed := phoneOTPPost(h.RequestPhoneOTP, `{"tenant_slug":"closed","phone":"+254711000001"}`)
	if open.Code != http.StatusOK || closed.Code != http.StatusOK || open.Body.String() != closed.Body.String() {
		t.Fatalf("answers differ: %d %s / %d %s", open.Code, open.Body, closed.Code, closed.Body)
	}
	if len(svc.sent) != 1 {
		t.Fatalf("codes sent = %d, want 1 (only the opted-in tenant)", len(svc.sent))
	}

	t.Run("verify signs the new phone up and returns tokens", func(t *testing.T) {
		code := "123456"
		_ = h.redis.Set(context.Background(), h.phoneOTPKey("open", "+254711000009"), hashOTP(code), time.Minute).Err()
		rec := phoneOTPPost(h.VerifyPhoneOTP, `{"tenant_slug":"open","phone":"+254711000009","code":"123456","client_id":"hadia-ui"}`)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"access_token":"access"`) {
			t.Fatalf("verify: %d %s", rec.Code, rec.Body)
		}
		if len(svc.logins) != 1 || svc.logins[0].Signup == nil {
			t.Fatal("login did not get the signup target")
		}
	})

	t.Run("wrong code never reaches signup", func(t *testing.T) {
		_ = h.redis.Set(context.Background(), h.phoneOTPKey("open", "+254711000010"), hashOTP("111111"), time.Minute).Err()
		rec := phoneOTPPost(h.VerifyPhoneOTP, `{"tenant_slug":"open","phone":"+254711000010","code":"222222"}`)
		if rec.Code == http.StatusOK || len(svc.logins) != 1 {
			t.Fatalf("wrong code: %d, logins %d", rec.Code, len(svc.logins))
		}
	})

	t.Run("send rate limit is unchanged for signups", func(t *testing.T) {
		body := `{"tenant_slug":"open","phone":"+254711000011"}`
		for i := 0; i < maxCodeSends; i++ {
			if rec := phoneOTPPost(h.RequestPhoneOTP, body); rec.Code != http.StatusOK {
				t.Fatalf("send %d: %d", i+1, rec.Code)
			}
		}
		if rec := phoneOTPPost(h.RequestPhoneOTP, body); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("over the cap: %d, want 429", rec.Code)
		}
	})
}
