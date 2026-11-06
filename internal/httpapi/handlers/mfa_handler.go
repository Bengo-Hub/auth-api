package handlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"go.uber.org/zap"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/mfa"
)

// MFAHandler exposes TOTP enrollment and verification endpoints.
type MFAHandler struct {
	svc    *mfa.Service
	logger *zap.Logger
}

func NewMFAHandler(svc *mfa.Service, logger *zap.Logger) *MFAHandler {
	return &MFAHandler{svc: svc, logger: logger}
}

// totpStartRequest carries the current authenticator code when one is already enabled.
type totpStartRequest struct {
	CurrentCode string `json:"current_code"`
}

// StartTOTP begins setup of an authenticator app. Replacing an enabled one needs its current code,
// and an enrolment-only session (a password alone on a covered account) can never replace one.
func (h *MFAHandler) StartTOTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	if demoSelfServiceBlocked(claims) {
		writeError(w, http.StatusForbidden, "demo_account_restricted", demoAccountRestrictedMessage, nil)
		return
	}
	var req totpStartRequest
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
			return
		}
	}
	if claims.MFAEnrollmentRequired {
		req.CurrentCode = ""
	}
	userID := parseUUID(claims.Subject)
	resp, err := h.svc.StartTOTP(r.Context(), userID, claims.Email, req.CurrentCode)
	switch {
	case errors.Is(err, mfa.ErrAuthenticatorExists):
		writeError(w, http.StatusConflict, "authenticator_exists", "An authenticator app is already set up. Enter its current code to replace it.", nil)
		return
	case errors.Is(err, mfa.ErrInvalidCode):
		writeError(w, http.StatusUnauthorized, "invalid_totp", "invalid TOTP code", nil)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "server_error", "failed to start totp", nil)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

func (h *MFAHandler) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	if demoSelfServiceBlocked(claims) {
		writeError(w, http.StatusForbidden, "demo_account_restricted", demoAccountRestrictedMessage, nil)
		return
	}
	var req totpConfirmRequest
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid code", nil)
		return
	}
	userID := parseUUID(claims.Subject)
	if err := h.svc.ConfirmTOTP(r.Context(), userID, req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_code", "verification failed", nil)
		return
	}
	// The account now has a second factor: no other enrolment-only session (a password alone) may
	// stay usable, or a stale one could come back to it later.
	keep, _ := uuid.Parse(claims.SessionID)
	if _, err := h.svc.RevokeOtherEnrollmentSessions(r.Context(), userID, keep); err != nil {
		h.logger.Error("revoke enrolment-only sessions after totp confirm", zap.String("user_id", userID.String()), zap.Error(err))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "totp_enabled"})
}

type backupGenRequest struct {
	Count int `json:"count"`
}

func (h *MFAHandler) RegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	if demoSelfServiceBlocked(claims) {
		writeError(w, http.StatusForbidden, "demo_account_restricted", demoAccountRestrictedMessage, nil)
		return
	}
	var req backupGenRequest
	_ = decodeJSON(r, &req)
	userID := parseUUID(claims.Subject)
	// An enrolment-only session gets the first set of codes at the end of setup, and nothing more:
	// it must never be able to delete codes the account already holds.
	if claims.MFAEnrollmentRequired {
		has, err := h.svc.HasUnusedBackupCodes(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to generate codes", nil)
			return
		}
		if has {
			writeError(w, http.StatusConflict, "backup_codes_exist", "Sign in again with your authenticator to replace your backup codes.", nil)
			return
		}
	}
	codes, err := h.svc.RegenerateBackupCodes(r.Context(), userID, req.Count)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to generate codes", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

type backupConsumeRequest struct {
	Code string `json:"code"`
}

func (h *MFAHandler) ConsumeBackupCode(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	var req backupConsumeRequest
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid code", nil)
		return
	}
	okUse, err := h.svc.ConsumeBackupCode(r.Context(), parseUUID(claims.Subject), req.Code)
	if err != nil || !okUse {
		writeError(w, http.StatusBadRequest, "invalid_code", "backup code invalid", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}
