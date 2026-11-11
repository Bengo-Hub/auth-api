package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/services/auth"
)

// BusinessInviter signs business invites (auth.Service.IssueBusinessInvite).
type BusinessInviter interface {
	IssueBusinessInvite(in auth.BusinessInvite) (string, auth.BusinessInvite, error)
}

// WithBusinessInvites turns on POST /admin/business-invites. appURLs maps an app code to the
// address of its sign-up page base (its /join page receives the invite).
func (h *AdminHandler) WithBusinessInvites(b BusinessInviter, appURLs map[string]string) *AdminHandler {
	h.inviter = b
	h.inviteAppURLs = appURLs
	return h
}

type businessInviteRequest struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	OrgName string `json:"org_name"`
	UseCase string `json:"use_case"`
	App     string `json:"app"`
}

// InviteBusiness handles POST /api/v1/admin/business-invites (owner, 2026-11-11): a platform owner
// invites a NEW business to an app. The invitee gets an email with a link to the app's /join page,
// which starts SSO sign-up carrying the invite; the organisation they create is active at once,
// without the review a self-registered organisation waits for. Interactive platform owners only.
func (h *AdminHandler) InviteBusiness(w http.ResponseWriter, r *http.Request) {
	if !interactivePlatformOwner(r) {
		writeError(w, http.StatusForbidden, "forbidden", "only a platform owner can invite a business", nil)
		return
	}
	if h.inviter == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "business invites are not configured", nil)
		return
	}
	var req businessInviteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body", nil)
		return
	}
	base := strings.TrimRight(h.inviteAppURLs[strings.TrimSpace(req.App)], "/")
	if base == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "this app does not take business invites", nil)
		return
	}
	tok, inv, err := h.inviter.IssueBusinessInvite(auth.BusinessInvite{Email: req.Email, OrgName: req.OrgName, UseCase: req.UseCase, App: req.App})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	link := base + "/join?invite=" + url.QueryEscape(tok)

	// The email goes out from the platform tenant (notifications-api auth.business.invited.notify,
	// template auth/business_invite).
	pt, err := h.ent.Tenant.Query().Where(tenant.SlugEQ("codevertex")).Only(r.Context())
	if err != nil {
		h.logger.Error("business invite: platform tenant not found", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal_error", "could not send the invitation", nil)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = inv.Email
	}
	inviteID, _ := uuid.Parse(inv.ID)
	h.publishEvent(r.Context(), pt.ID, "auth.business", inviteID, "invited.notify", map[string]any{
		"tenant_id": pt.ID.String(),
		"email":     inv.Email,
		"name":      name,
		"org_name":  inv.OrgName,
		"login_url": link,
	})
	h.writeAudit(r, pt.ID, "business.invited", "business_invite", inv.ID, map[string]any{"email": inv.Email, "org_name": inv.OrgName, "app": inv.App})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": inv.ID, "email": inv.Email, "org_name": inv.OrgName, "app": inv.App, "expires_at": inv.ExpiresAt, "link": link,
	})
}
