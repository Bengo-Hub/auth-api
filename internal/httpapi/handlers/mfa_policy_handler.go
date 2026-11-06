package handlers

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
)

// MFA policy administration. Whether sign-in needs a second factor is a platform decision, so
// only a platform owner reads or edits it: the platform default (every tenant without its own
// policy) and each tenant's own policy. A tenant's admin cannot, and the generic tenant update
// never writes these keys. Every change is audited.

// mfaPolicyRolePattern is the shape of a role code in a policy.
var mfaPolicyRolePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// mfaPolicyMaxRoles bounds how many role codes one policy lists.
const mfaPolicyMaxRoles = 100

type mfaPolicyRequest struct {
	RequiredRoles []string `json:"required_roles"`
	AllAccounts   bool     `json:"all_accounts"`
	// Inherit (tenant policy only) removes the tenant's own policy so it follows the platform
	// default again.
	Inherit bool `json:"inherit"`
}

// requirePlatformOwner admits only a platform owner's session: not a tenant admin, and not an
// admin-scoped service token.
func requirePlatformOwner(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	return ok && claims != nil && claims.IsPlatformOwner
}

func (req mfaPolicyRequest) policy() (auth.MFAPolicy, error) {
	if len(req.RequiredRoles) > mfaPolicyMaxRoles {
		return auth.MFAPolicy{}, errors.New("too many roles")
	}
	for _, r := range req.RequiredRoles {
		// Normalized trims each code below, so a stray space is not an invalid role.
		if !mfaPolicyRolePattern.MatchString(strings.TrimSpace(r)) {
			return auth.MFAPolicy{}, errors.New("invalid role code: " + r)
		}
	}
	return auth.MFAPolicy{RequiredRoles: req.RequiredRoles, AllAccounts: req.AllAccounts}.Normalized(), nil
}

// GetPlatformMFAPolicy returns the platform default MFA policy.
// GET /api/v1/admin/mfa-policy
func (h *RBACHandler) GetPlatformMFAPolicy(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformOwner(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform owner required", nil)
		return
	}
	view, err := h.svc.GetPlatformMFAPolicy(r.Context())
	if err != nil {
		h.logger.Error("get platform mfa policy", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load policy", nil)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// UpdatePlatformMFAPolicy replaces the platform default MFA policy.
// PATCH /api/v1/admin/mfa-policy  body: {required_roles, all_accounts}
func (h *RBACHandler) UpdatePlatformMFAPolicy(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformOwner(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform owner required", nil)
		return
	}
	var req mfaPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	p, err := req.policy()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error(), nil)
		return
	}
	before, _ := h.svc.PlatformMFAPolicyDefault(r.Context())
	view, err := h.svc.SetPlatformMFAPolicy(r.Context(), p)
	if err != nil {
		h.logger.Error("set platform mfa policy", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update policy", nil)
		return
	}
	h.writeAudit(r, "auth.mfa_policy.updated", "mfa_policy", "platform", map[string]any{
		"scope":           "platform",
		"required_roles":  p.RequiredRoles,
		"all_accounts":    p.AllAccounts,
		"previous_roles":  before.RequiredRoles,
		"previous_all_on": before.AllAccounts,
	})
	writeJSON(w, http.StatusOK, view)
}

// ResetUserMFA removes a user's authenticator app and backup codes and ends every session, for a
// person who lost their phone. Only a platform owner may do it, after confirming who is asking
// outside the system; it is audited. A covered account then gets an enrolment-only session at its
// next sign-in and sets up a new authenticator.
// POST /api/v1/admin/users/{user_id}/mfa-reset
func (h *RBACHandler) ResetUserMFA(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformOwner(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform owner required", nil)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}
	res, err := h.svc.ResetUserMFA(r.Context(), userID)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user_not_found", "user not found", nil)
			return
		}
		h.logger.Error("reset user mfa", zap.String("user_id", userID.String()), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not reset the authenticator", nil)
		return
	}
	h.writeAudit(r, "auth.mfa.reset", "user", userID.String(), map[string]any{
		"had_authenticator": res.HadAuthenticator,
		"sessions_revoked":  res.SessionsRevoked,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                userID,
		"had_authenticator": res.HadAuthenticator,
		"sessions_revoked":  res.SessionsRevoked,
	})
}

// GetTenantMFAPolicy returns a tenant's MFA policy, whether it follows the platform default, and
// the roles to pick from.
// GET /api/v1/admin/tenants/{tenant_id}/mfa-policy
func (h *RBACHandler) GetTenantMFAPolicy(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformOwner(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform owner required", nil)
		return
	}
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tenant id", nil)
		return
	}
	view, err := h.svc.GetTenantMFAPolicy(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, auth.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found", nil)
			return
		}
		h.logger.Error("get tenant mfa policy", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load policy", nil)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// UpdateTenantMFAPolicy sets a tenant's own MFA policy, or with inherit removes it.
// PATCH /api/v1/admin/tenants/{tenant_id}/mfa-policy  body: {required_roles, all_accounts, inherit}
func (h *RBACHandler) UpdateTenantMFAPolicy(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformOwner(r) {
		writeError(w, http.StatusForbidden, "forbidden", "platform owner required", nil)
		return
	}
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tenant id", nil)
		return
	}
	var req mfaPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	p, err := req.policy()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error(), nil)
		return
	}
	before, beforeErr := h.svc.GetTenantMFAPolicy(r.Context(), tenantID)
	if beforeErr != nil && errors.Is(beforeErr, auth.ErrTenantNotFound) {
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found", nil)
		return
	}
	view, err := h.svc.SetTenantMFAPolicy(r.Context(), tenantID, p, req.Inherit)
	if err != nil {
		if errors.Is(err, auth.ErrTenantNotFound) {
			writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found", nil)
			return
		}
		h.logger.Error("set tenant mfa policy", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update policy", nil)
		return
	}
	extra := map[string]any{
		"scope":          "tenant",
		"tenant_id":      tenantID.String(),
		"inherit":        req.Inherit,
		"required_roles": p.RequiredRoles,
		"all_accounts":   p.AllAccounts,
	}
	if before != nil {
		extra["previous_inherited"] = before.Inherited
		extra["previous_roles"] = before.Policy.RequiredRoles
		extra["previous_all_on"] = before.Policy.AllAccounts
	}
	h.writeAudit(r, "auth.mfa_policy.updated", "mfa_policy", tenantID.String(), extra)
	writeJSON(w, http.StatusOK, view)
}
