package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/services/auth"
)

func TestNormalizeLookupPhone(t *testing.T) {
	for in, want := range map[string]string{
		"+254712345678": "+254712345678",
		"254712345678":  "+254712345678",
		"0712345678":    "+254712345678",
		" 0712345678 ":  "+254712345678",
		"+447400123456": "+447400123456",
	} {
		got, err := normalizeLookupPhone(in)
		if err != nil || got != want {
			t.Errorf("normalizeLookupPhone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "12", "+999"} {
		if _, err := normalizeLookupPhone(bad); err == nil {
			t.Errorf("normalizeLookupPhone(%q) accepted", bad)
		}
	}
}

type phoneLookupFake struct {
	AuthService
	got  string
	user *auth.PhoneUser
}

func (f *phoneLookupFake) LookupVerifiedPhone(_ context.Context, e164 string) (*auth.PhoneUser, error) {
	f.got = e164
	if f.user == nil {
		return nil, auth.ErrPhoneNotFound
	}
	return f.user, nil
}

func TestS2SUserByPhone(t *testing.T) {
	uid := uuid.New()
	known := &phoneLookupFake{user: &auth.PhoneUser{UserID: uid, PhoneVerified: true, Tenants: []auth.PhoneUserTenant{{TenantID: uuid.New(), Slug: "acme", Roles: []string{"admin"}}}}}
	h := &AuthHandler{service: known, logger: zap.NewNop()}

	rec := httptest.NewRecorder()
	h.S2SUserByPhone(rec, httptest.NewRequest(http.MethodGet, "/api/v1/s2s/users/by-phone?phone=0712345678", nil))
	if rec.Code != http.StatusOK || known.got != "+254712345678" {
		t.Fatalf("known phone: status %d, looked up %q", rec.Code, known.got)
	}
	var body auth.PhoneUser
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.UserID != uid || !body.PhoneVerified || len(body.Tenants) != 1 || body.Tenants[0].Slug != "acme" {
		t.Fatalf("body %s, err %v", rec.Body.String(), err)
	}

	unknown := &AuthHandler{service: &phoneLookupFake{}, logger: zap.NewNop()}
	rec = httptest.NewRecorder()
	unknown.S2SUserByPhone(rec, httptest.NewRequest(http.MethodGet, "/api/v1/s2s/users/by-phone?phone=%2B254712345678", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unverified or unknown phone: status %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	unknown.S2SUserByPhone(rec, httptest.NewRequest(http.MethodGet, "/api/v1/s2s/users/by-phone?phone=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad phone: status %d, want 400", rec.Code)
	}
}
