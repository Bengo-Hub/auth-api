package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// --- My Email Addresses (Zoho-style multi-email account settings) ---
//
// Add is a two-step flow reusing the SAME OTP engine as SendMyEmailCode/
// VerifyMyEmailCode (redis-backed 10-minute code, rate-limited) — it just
// creates a new UserEmail row instead of replacing the primary User.email
// column. See internal/services/auth/contacts.go for the persistence layer.

// ListMyEmails returns every additional email address on the caller's account.
// GET /api/v1/auth/me/emails
func (h *AuthHandler) ListMyEmails(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	rows, err := h.service.ListUserEmails(r.Context(), userID)
	if err != nil {
		h.logger.Error("list user emails", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not load email addresses", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, e := range rows {
		out = append(out, map[string]any{
			"id":          e.ID,
			"email":       e.Email,
			"is_verified": e.IsVerified,
			"is_primary":  e.IsPrimary,
			"created_at":  e.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"emails": out})
}

// SendAddEmailCode sends a one-time code to prove ownership of a NEW address
// before it's added to the account. POST /api/v1/auth/me/emails/send-code
// body: {email}
func (h *AuthHandler) SendAddEmailCode(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "email verification not configured", nil)
		return
	}
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	email := normalizeSignupEmail(req.Email)
	if email == "" || !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "invalid_request", "a valid email is required", nil)
		return
	}
	if h.service.EmailTakenByOther(r.Context(), email, userID) {
		writeError(w, http.StatusConflict, "email_exists", "That email is already used by another account.", nil)
		return
	}

	rateKey := h.redisNamespace + ":verify:otp:rate:" + userID.String()
	count, _ := h.redis.Incr(r.Context(), rateKey).Result()
	if count == 1 {
		_ = h.redis.Expire(r.Context(), rateKey, 10*time.Minute).Err()
	}
	if count > 5 {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many verification attempts. Please try again later.", nil)
		return
	}

	otp, err := generateOTP()
	if err != nil {
		h.logger.Error("generate add-email otp", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate code", nil)
		return
	}
	_ = h.redis.Set(r.Context(), h.myEmailOTPKey(userID, email), hashOTP(otp), 10*time.Minute).Err()

	tenantID := uuid.Nil
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims != nil && claims.TenantID != "" {
		tenantID, _ = uuid.Parse(claims.TenantID)
	}
	h.service.SendOTPEmail(r.Context(), tenantID, userID, email, otp)

	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// VerifyAddEmailCode confirms the code and adds the address as a new,
// verified UserEmail row. POST /api/v1/auth/me/emails/verify-code
// body: {email, code}
func (h *AuthHandler) VerifyAddEmailCode(w http.ResponseWriter, r *http.Request) {
	if h.redis == nil || h.redisNamespace == "" {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "email verification not configured", nil)
		return
	}
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	email := normalizeSignupEmail(req.Email)
	code := strings.TrimSpace(req.Code)
	if email == "" || code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email and code are required", nil)
		return
	}

	key := h.myEmailOTPKey(userID, email)
	stored, err := h.redis.Get(r.Context(), key).Result()
	if err != nil {
		writeError(w, http.StatusBadRequest, "code_expired", "The code has expired or was not sent. Request a new one.", nil)
		return
	}
	if stored != hashOTP(code) {
		writeError(w, http.StatusBadRequest, "code_invalid", "The verification code is incorrect.", nil)
		return
	}
	_ = h.redis.Del(r.Context(), key).Err()

	created, err := h.service.AddVerifiedUserEmail(r.Context(), userID, email)
	if err != nil {
		if errors.Is(err, auth.ErrEmailAlreadyExists) {
			writeError(w, http.StatusConflict, "email_exists", "That email is already used by another account.", nil)
			return
		}
		h.logger.Error("add verified user email", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not add email", nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": created.ID, "email": created.Email})
}

// SetPrimaryMyEmail marks one of the caller's own additional addresses primary.
// POST /api/v1/auth/me/emails/{id}/primary
func (h *AuthHandler) SetPrimaryMyEmail(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}
	if err := h.service.SetPrimaryUserEmail(r.Context(), userID, id); err != nil {
		if errors.Is(err, auth.ErrContactNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "email address not found", nil)
			return
		}
		h.logger.Error("set primary user email", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not update email", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DeleteMyEmail removes one of the caller's own additional addresses.
// DELETE /api/v1/auth/me/emails/{id}
func (h *AuthHandler) DeleteMyEmail(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}
	if err := h.service.DeleteUserEmail(r.Context(), userID, id); err != nil {
		if errors.Is(err, auth.ErrContactNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "email address not found", nil)
			return
		}
		h.logger.Error("delete user email", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not delete email", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- My Mobile Numbers ---
//
// No SMS-OTP provider is wired anywhere in this platform yet, so these are
// added as unverified contact info only (is_verified always false) — see
// project_sso_accounts_portal_revamp.md for why real verification is
// deliberately out of scope for this pass rather than a silent gap.

// ListMyPhones returns every registered mobile number on the caller's account.
// GET /api/v1/auth/me/phones
func (h *AuthHandler) ListMyPhones(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	rows, err := h.service.ListUserPhones(r.Context(), userID)
	if err != nil {
		h.logger.Error("list user phones", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not load mobile numbers", nil)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, map[string]any{
			"id":          p.ID,
			"phone":       p.Phone,
			"is_verified": p.IsVerified,
			"is_primary":  p.IsPrimary,
			"created_at":  p.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"phones": out})
}

// AddMyPhone registers a new mobile number. POST /api/v1/auth/me/phones
// body: {phone}
func (h *AuthHandler) AddMyPhone(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON payload", nil)
		return
	}
	phone := strings.TrimSpace(req.Phone)
	if phone == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "a phone number is required", nil)
		return
	}
	created, err := h.service.AddUserPhone(r.Context(), userID, phone)
	if err != nil {
		if errors.Is(err, auth.ErrPhoneAlreadyExists) {
			writeError(w, http.StatusConflict, "phone_exists", "That number is already registered on your account.", nil)
			return
		}
		h.logger.Error("add user phone", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not add phone number", nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": created.ID, "phone": created.Phone})
}

// SetPrimaryMyPhone marks one of the caller's own numbers primary.
// POST /api/v1/auth/me/phones/{id}/primary
func (h *AuthHandler) SetPrimaryMyPhone(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}
	if err := h.service.SetPrimaryUserPhone(r.Context(), userID, id); err != nil {
		if errors.Is(err, auth.ErrContactNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "phone number not found", nil)
			return
		}
		h.logger.Error("set primary user phone", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not update phone number", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DeleteMyPhone removes one of the caller's own numbers.
// DELETE /api/v1/auth/me/phones/{id}
func (h *AuthHandler) DeleteMyPhone(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.myUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth context", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}
	if err := h.service.DeleteUserPhone(r.Context(), userID, id); err != nil {
		if errors.Is(err, auth.ErrContactNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "phone number not found", nil)
			return
		}
		h.logger.Error("delete user phone", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not delete phone number", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
