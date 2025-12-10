package handlers

import (
	"net/http"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/mfa"
	"go.uber.org/zap"
)

// MFAHandler exposes TOTP enrollment and verification endpoints.
type MFAHandler struct {
	svc    *mfa.Service
	logger *zap.Logger
}

func NewMFAHandler(svc *mfa.Service, logger *zap.Logger) *MFAHandler {
	return &MFAHandler{svc: svc, logger: logger}
}

func (h *MFAHandler) StartTOTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing auth", nil)
		return
	}
	userID := parseUUID(claims.Subject)
	resp, err := h.svc.StartTOTP(r.Context(), userID, claims.Email)
	if err != nil {
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
	var req totpConfirmRequest
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid code", nil)
		return
	}
	if err := h.svc.ConfirmTOTP(r.Context(), parseUUID(claims.Subject), req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_code", "verification failed", nil)
		return
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
	var req backupGenRequest
	_ = decodeJSON(r, &req)
	codes, err := h.svc.RegenerateBackupCodes(r.Context(), parseUUID(claims.Subject), req.Count)
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
