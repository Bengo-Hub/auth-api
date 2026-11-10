package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/services/auth"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
)

// memberStatusInvited is a membership waiting for its person to accept. It grants nothing: every
// sign-in, token and role lookup reads active memberships only (audit H2).
const memberStatusInvited = "invited"

// needsMemberConsent reports whether a new membership must wait for the person to accept (audit
// H4, owner decision 2026-11-10): always for an account that existed before this add, except when
// a signed-in platform owner adds them. A brand-new account (made by this add, set-password link
// emailed) joins at once.
func needsMemberConsent(accountCreatedNow, interactivePlatformOwner, portalAdd bool) bool {
	return !accountCreatedNow && !interactivePlatformOwner && !portalAdd
}

// isPortalAdd is a resident or customer added to a portal by phone with portal roles only (Maskani
// owners and occupants, customers, learners, riders). They get only their own portal and never use
// the accounts site, so they join at once (owner, 2026-11-10). Any staff role needs acceptance.
func isPortalAdd(phone string, roles []string) bool {
	if strings.TrimSpace(phone) == "" || len(roles) == 0 {
		return false
	}
	for _, r := range roles {
		if !auth.IsSelfServiceRole(r) {
			return false
		}
	}
	return true
}

// interactivePlatformOwner is a signed-in platform owner, not a service key: the S2S member route
// stamps platform claims with no subject, so a service add (MarketFlow, POS) still needs consent.
func interactivePlatformOwner(r *http.Request) bool {
	c, ok := authmiddleware.ClaimsFromContext(r.Context())
	return ok && c != nil && c.IsPlatformOwner && strings.TrimSpace(c.Subject) != ""
}

// notifyMemberInvite emails the invited person (notifications-api auth.membership.invited.notify,
// template auth/membership_invite).
func (h *AdminHandler) notifyMemberInvite(ctx context.Context, tenantID, userID uuid.UUID) {
	u, err := h.ent.User.Get(ctx, userID)
	if err != nil || u.Email == "" || strings.HasSuffix(strings.ToLower(u.Email), ".local") {
		return
	}
	orgName := ""
	if t, tErr := h.ent.Tenant.Get(ctx, tenantID); tErr == nil {
		orgName = t.Name
	}
	h.publishEvent(ctx, tenantID, "auth.membership", userID, "invited.notify", map[string]any{
		"tenant_id": tenantID.String(),
		"email":     u.Email,
		"name":      profileStr(u.Profile, "name"),
		"org_name":  orgName,
		"login_url": strings.TrimRight(h.authUIURL, "/") + "/invitations",
	})
}

type invitationView struct {
	TenantID   string   `json:"tenant_id"`
	TenantName string   `json:"tenant_name"`
	TenantSlug string   `json:"tenant_slug"`
	Roles      []string `json:"roles"`
	InvitedAt  string   `json:"invited_at"`
}

func callerUserID(r *http.Request) (uuid.UUID, bool) {
	c, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || c == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(c.Subject)
	return id, err == nil
}

// MyInvitations lists the organisations waiting for the signed-in person to accept.
// GET /api/v1/me/invitations
func (h *AdminHandler) MyInvitations(w http.ResponseWriter, r *http.Request) {
	userID, ok := callerUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "sign in first", nil)
		return
	}
	rows, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.UserID(userID), tenantmembership.StatusEQ(memberStatusInvited)).
		WithTenant().All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not list invitations", nil)
		return
	}
	out := make([]invitationView, 0, len(rows))
	for _, m := range rows {
		v := invitationView{TenantID: m.TenantID.String(), Roles: m.Roles, InvitedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00")}
		if t := m.Edges.Tenant; t != nil {
			v.TenantName, v.TenantSlug = t.Name, t.Slug
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": out})
}

// myInvitation loads the signed-in person's own pending membership in {tenant_id}.
func (h *AdminHandler) myInvitation(w http.ResponseWriter, r *http.Request) (*ent.TenantMembership, uuid.UUID, bool) {
	userID, ok := callerUserID(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "sign in first", nil)
		return nil, uuid.Nil, false
	}
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return nil, uuid.Nil, false
	}
	m, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.UserID(userID), tenantmembership.TenantID(tenantID), tenantmembership.StatusEQ(memberStatusInvited)).
		Only(r.Context())
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no pending invitation from this organisation", nil)
		return nil, uuid.Nil, false
	}
	return m, userID, true
}

// AcceptInvitation makes the person a member. Only they can: a tenant admin cannot turn an
// invitation into a membership (UpdateTenantMember refuses it).
// POST /api/v1/me/invitations/{tenant_id}/accept
func (h *AdminHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	m, userID, ok := h.myInvitation(w, r)
	if !ok {
		return
	}
	m, err := m.Update().SetStatus("active").Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not accept the invitation", nil)
		return
	}
	// Downstream services set the person up now, as for any new member.
	if u, uErr := h.ent.User.Get(r.Context(), userID); uErr == nil {
		slug := ""
		if t, tErr := h.ent.Tenant.Get(r.Context(), m.TenantID); tErr == nil {
			slug = t.Slug
		}
		payload := map[string]any{
			"user_id": userID.String(), "email": u.Email, "full_name": profileStr(u.Profile, "name"),
			"phone": profileStr(u.Profile, "phone"), "tenant_id": m.TenantID.String(), "tenant_slug": slug,
			"roles": m.Roles, "method": "invitation_accepted", "email_verified": u.EmailVerified,
			"skip_welcome": true,
		}
		if m.OutletID != nil {
			payload["outlet_id"] = m.OutletID.String()
		}
		if len(m.OutletIds) > 0 {
			payload["outlet_ids"] = m.OutletIds
		}
		h.publishEvent(r.Context(), m.TenantID, "auth.user", userID, "created", payload)
	}
	h.writeAudit(r, m.TenantID, "auth.tenant_member.invitation_accepted", "tenant_membership", userID.String(), nil)
	h.logger.Info("invitation accepted", zap.String("tenant_id", m.TenantID.String()), zap.String("user_id", userID.String()))
	writeJSON(w, http.StatusOK, map[string]any{"status": "active", "tenant_id": m.TenantID.String()})
}

// DeclineInvitation removes the pending membership.
// POST /api/v1/me/invitations/{tenant_id}/decline
func (h *AdminHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	m, userID, ok := h.myInvitation(w, r)
	if !ok {
		return
	}
	if err := h.ent.TenantMembership.DeleteOne(m).Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not decline the invitation", nil)
		return
	}
	h.writeAudit(r, m.TenantID, "auth.tenant_member.invitation_declined", "tenant_membership", userID.String(), nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "declined", "tenant_id": m.TenantID.String()})
}
