package handlers

import (
	"net/http"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// portalResetRoles are the only roles an S2S portal password reset may touch. A person who also
// holds any other role (staff, admin, owner) is never reachable through this route.
var portalResetRoles = map[string]bool{"student": true, "parent": true}

// portalResetDenial explains why a portal account cannot have its temporary password reissued,
// or returns "" when it can. The reset exists so an owning service can resend credentials that
// never reached a learner or parent, so it applies only to an account that was never claimed:
// every role must be a portal role and the person must still be on the temporary password.
func portalResetDenial(roles []string, profile map[string]any) string {
	if len(roles) == 0 {
		return "not_a_member"
	}
	for _, role := range roles {
		if !portalResetRoles[role] {
			return "not_a_portal_account"
		}
	}
	if pending, _ := profile["must_change_password"].(bool); !pending {
		return "already_claimed"
	}
	return ""
}

// S2SPortalPasswordReset reissues the temporary password of an unclaimed student or parent
// account so the owning service can send the credentials again.
// POST /api/v1/s2s/tenants/{tenant_id}/members/{user_id}/portal-password
// The password is returned once and never stored in plaintext. The route is deliberately narrow:
// a service key cannot use it on staff, on an account the person already took over, or on a user
// outside the given tenant.
func (h *UserHandler) S2SPortalPasswordReset(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tenant ID", nil)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid user ID", nil)
		return
	}

	member, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.UserID(userID), tenantmembership.TenantID(tenantID)).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "the user is not a member of this tenant", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load membership", nil)
		return
	}
	u, err := h.ent.User.Get(r.Context(), userID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load user", nil)
		return
	}

	switch portalResetDenial(member.Roles, u.Profile) {
	case "":
	case "already_claimed":
		writeError(w, http.StatusConflict, "already_claimed", "the person already replaced the temporary password; use the password reset email instead", nil)
		return
	default:
		writeError(w, http.StatusForbidden, "forbidden", "only a student or parent portal account can be reset this way", nil)
		return
	}

	newPassword := generateTempPassword()
	hash, err := h.hasher.Hash(newPassword)
	if err != nil {
		h.logger.Error("hash portal password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not reset password", nil)
		return
	}
	profile := make(map[string]any, len(u.Profile)+1)
	for k, v := range u.Profile {
		profile[k] = v
	}
	profile["must_change_password"] = true
	if err := h.ent.User.UpdateOneID(userID).SetPasswordHash(hash).SetProfile(profile).Exec(r.Context()); err != nil {
		h.logger.Error("reissue portal password", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not reset password", nil)
		return
	}
	h.invalidateMeCache(r.Context(), userID)
	h.logger.Info("portal temporary password reissued", zap.String("user_id", userID.String()), zap.String("tenant_id", tenantID.String()))

	writeJSON(w, http.StatusOK, map[string]any{"user_id": userID, "temp_password": newPassword})
}
