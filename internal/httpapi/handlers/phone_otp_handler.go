package handlers

import (
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Phone code sign-in for customer portals (Maskani owners and occupants). Codes reuse the same
// engine as the email codes: SHA-256 hash in Redis, 5 minute expiry, atomic check with an attempt
// cap, and at most 5 sends per phone per 10 minutes. The route also carries the sensitive IP limit.

const phoneOTPTTL = 5 * time.Minute

type phoneOTPRequest struct {
	TenantSlug string `json:"tenant_slug"`
	Phone      string `json:"phone"`
	Code       string `json:"code"`
	ClientID   string `json:"client_id"`
}

func (h *AuthHandler) phoneOTPKey(tenantSlug, phone string) string {
	return h.redisNamespace + ":phone_login:otp:" + strings.ToLower(strings.TrimSpace(tenantSlug)) + ":" + phone
}

// RequestPhoneOTP sends a sign-in code to a phone on file for an active member of the tenant.
// The response is the same whether or not the phone belongs to a member, so it cannot be used to
// discover accounts.
// POST /api/v1/auth/phone/otp/request  body: {tenant_slug, phone}
func (h *AuthHandler) RequestPhoneOTP(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "phone sign-in not configured", nil)
		return
	}
	var req phoneOTPRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.TenantSlug) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant_slug and phone are required", nil)
		return
	}
	phone, err := validateAndNormalizePhone(strings.TrimSpace(req.Phone))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_phone", "Enter the phone number with its country code.", nil)
		return
	}
	if !h.allowCodeSend(r.Context(), h.phoneOTPKey(req.TenantSlug, phone)+":rate") {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many codes requested. Please try again later.", nil)
		return
	}
	accepted := map[string]any{"sent": true, "expires_in": int(phoneOTPTTL.Seconds())}
	target, err := h.service.FindPhoneLoginTarget(r.Context(), req.TenantSlug, phone)
	if err != nil {
		writeJSON(w, http.StatusOK, accepted)
		return
	}
	otp, err := generateOTP()
	if err != nil {
		h.logger.Error("phone otp: generate", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate code", nil)
		return
	}
	if err := h.redis.Set(r.Context(), h.phoneOTPKey(req.TenantSlug, phone), hashOTP(otp), phoneOTPTTL).Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "could not store the code", nil)
		return
	}
	h.service.SendPhoneOTP(r.Context(), target, otp, phoneOTPTTL)
	writeJSON(w, http.StatusOK, accepted)
}

// VerifyPhoneOTP checks the code and returns the standard token pair.
// POST /api/v1/auth/phone/otp/verify  body: {tenant_slug, phone, code, client_id}
func (h *AuthHandler) VerifyPhoneOTP(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "phone sign-in not configured", nil)
		return
	}
	var req phoneOTPRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.TenantSlug) == "" || strings.TrimSpace(req.Code) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant_slug, phone and code are required", nil)
		return
	}
	phone, err := validateAndNormalizePhone(strings.TrimSpace(req.Phone))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_phone", "Enter the phone number with its country code.", nil)
		return
	}
	if res := h.checkCode(r.Context(), h.phoneOTPKey(req.TenantSlug, phone), strings.TrimSpace(req.Code)); res != codeOK {
		writeCodeError(w, res, "otp")
		return
	}
	target, err := h.service.FindPhoneLoginTarget(r.Context(), req.TenantSlug, phone)
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	// A phone code replaces the password, so it must never bypass an account's own second factor.
	if mfaOn, _ := h.service.IsMFAEnabled(r.Context(), target.User.ID); mfaOn {
		writeError(w, http.StatusForbidden, "mfa_required", "This account uses an authenticator app. Sign in with your password.", nil)
		return
	}
	result, err := h.service.LoginWithPhoneOTP(r.Context(), target, req.ClientID, clientIP(r), userAgent(r))
	if err != nil {
		h.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, h.toAuthResponse(result))
}
