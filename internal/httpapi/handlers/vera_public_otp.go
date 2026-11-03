package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Public email codes for the Vera widget. A visitor who is not signed in proves an email
// address before the widget opens a support ticket for it: the code goes to the address, the
// verified code becomes a short-lived otp_token, and ticketing-api trades that token for the
// verified address through the S2S validate route below. The signed-in twin is SendOTP and
// VerifyOTP; both issue the same token shape, so validate serves either.

const (
	publicOTPTTL      = 10 * time.Minute
	publicOTPTokenTTL = 10 * time.Minute
)

func (h *AuthHandler) publicOTPKey(email string) string {
	return h.redisNamespace + ":vera:public:otp:" + normalizeSignupEmail(email)
}

func (h *AuthHandler) publicOTPRateKey(email string) string {
	return h.redisNamespace + ":vera:public:otp:rate:" + normalizeSignupEmail(email)
}

// publicOTPEmail returns the normalised address, or "" when it is not a plain valid address.
func publicOTPEmail(raw string) string {
	email := normalizeSignupEmail(raw)
	if len(email) > 254 {
		return ""
	}
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
		return ""
	}
	return email
}

// SendPublicOTP emails a 6-digit code to the address a widget visitor typed.
// POST /api/v1/auth/public-otp/send  body: {email, tenant_slug?}
// Held per IP at the router and to 5 codes per address per 10 minutes here.
func (h *AuthHandler) SendPublicOTP(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "OTP service not configured", nil)
		return
	}
	var req struct {
		Email      string `json:"email"`
		TenantSlug string `json:"tenant_slug"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	email := publicOTPEmail(req.Email)
	if email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "a valid email is required", nil)
		return
	}
	if !h.allowCodeSend(r.Context(), h.publicOTPRateKey(email)) {
		writeError(w, http.StatusTooManyRequests, "rate_limited",
			"Too many codes requested. Please try again later.", nil)
		return
	}
	otp, err := generateOTP()
	if err != nil {
		h.logger.Error("generate public otp", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate code", nil)
		return
	}
	_ = h.redis.Set(r.Context(), h.publicOTPKey(email), hashOTP(otp), publicOTPTTL).Err()

	// Brand the email as the widget's tenant when it exists, else the platform tenant.
	brandingSlug := strings.TrimSpace(req.TenantSlug)
	if brandingSlug == "" {
		brandingSlug = "codevertex"
	}
	tenantID := uuid.Nil
	if t, terr := h.service.GetTenantBySlug(r.Context(), brandingSlug); terr == nil && t != nil {
		tenantID = t.ID
	} else if t, terr := h.service.GetTenantBySlug(r.Context(), "codevertex"); terr == nil && t != nil {
		tenantID = t.ID
	}
	// A fresh id per send, so notifications-api's idempotency key does not swallow a resend.
	h.service.SendOTPEmail(r.Context(), tenantID, uuid.New(), email, otp)

	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// VerifyPublicOTP checks the code and returns an otp_token for ticketing-api.
// POST /api/v1/auth/public-otp/verify  body: {email, otp}
func (h *AuthHandler) VerifyPublicOTP(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "OTP service not configured", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	email := publicOTPEmail(req.Email)
	code := strings.TrimSpace(req.OTP)
	if email == "" || code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email and otp are required", nil)
		return
	}
	if res := h.checkCode(r.Context(), h.publicOTPKey(email), code); res != codeOK {
		writeCodeError(w, res, "otp")
		return
	}
	token, err := h.issueOTPToken(r, map[string]any{"email": email, "anonymous": true})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to issue token", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true, "otp_token": token})
}

// issueOTPToken stores the payload under a random token for publicOTPTokenTTL and returns the
// token. Only its hash is kept in Redis.
func (h *AuthHandler) issueOTPToken(r *http.Request, payload map[string]any) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	body, _ := json.Marshal(payload)
	if err := h.redis.Set(r.Context(), h.otpTokenKey(hashOTP(token)), string(body), publicOTPTokenTTL).Err(); err != nil {
		return "", err
	}
	return token, nil
}

// S2SValidateOTPToken trades an otp_token for the verified address, once.
// GET /api/v1/s2s/otp/validate?token=  (X-API-Key)
// Answers 200 {valid, email}; an unknown, expired or used token is 200 {valid:false}.
func (h *AuthHandler) S2SValidateOTPToken(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "OTP service not configured", nil)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "token is required", nil)
		return
	}
	// GETDEL: a token opens one ticket, never two.
	raw, err := h.redis.GetDel(r.Context(), h.otpTokenKey(hashOTP(token))).Result()
	if err != nil || raw == "" {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false})
		return
	}
	var payload struct {
		Email string `json:"email"`
	}
	if json.Unmarshal([]byte(raw), &payload) != nil || payload.Email == "" {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "email": payload.Email})
}
