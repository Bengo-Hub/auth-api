package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
)

// tenantByRef resolves an S2S {tenant} path value: a UUID first, then a slug. Not found is an
// ent NotFound error.
func (h *AdminHandler) tenantByRef(ctx context.Context, ref string) (*ent.Tenant, error) {
	if tid, err := uuid.Parse(ref); err == nil {
		t, err := h.ent.Tenant.Get(ctx, tid)
		if err == nil || !ent.IsNotFound(err) {
			return t, err
		}
	}
	return h.ent.Tenant.Query().Where(tenant.SlugEQ(ref)).Only(ctx)
}

// billingContactAdmin is one active member who may receive the tenant's bills.
type billingContactAdmin struct {
	Roles        []string
	PrimaryPhone string // verified or primary user_phones entry
	ProfilePhone string // profile.phone
	Email        string
}

// isBillingAdminRole: the tenant's own administrators (admin, pos_admin, ...). superuser and
// super_admin are left out: on a tenant those are platform staff, never the business paying.
func isBillingAdminRole(roles []string) bool {
	for _, r := range roles {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "superuser" || r == "super_admin" {
			return false
		}
	}
	for _, r := range roles {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "admin" || r == "owner" || strings.HasSuffix(r, "_admin") {
			return true
		}
	}
	return false
}

// outletContactPhone reads an outlet's phone from metadata: contact_phones [{label, value}] (the
// outlet form) or a plain phone.
func outletContactPhone(meta map[string]any) string {
	if list, ok := meta["contact_phones"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if v, _ := m["value"].(string); strings.TrimSpace(v) != "" {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	for _, k := range []string{"phone", "contact_phone"} {
		if v, _ := meta[k].(string); strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// pickBillingPhone is the one rule for where a tenant's bills go by phone: the first tenant
// administrator with a phone (their primary phone, else the profile phone), else the head office
// outlet's phone, else the tenant's own contact phone. Source says which one answered.
func pickBillingPhone(admins []billingContactAdmin, hqPhone, tenantPhone string) (phone, source string) {
	for _, a := range admins {
		if !isBillingAdminRole(a.Roles) {
			continue
		}
		if p := strings.TrimSpace(a.PrimaryPhone); p != "" {
			return p, "tenant_admin"
		}
		if p := strings.TrimSpace(a.ProfilePhone); p != "" {
			return p, "tenant_admin"
		}
	}
	if p := strings.TrimSpace(hqPhone); p != "" {
		return p, "main_outlet"
	}
	if p := strings.TrimSpace(tenantPhone); p != "" {
		return p, "tenant"
	}
	return "", ""
}

// S2STenantBillingContact answers where a tenant's billing messages go by phone (see
// pickBillingPhone). notifications-api uses it to send subscription invoices and payment
// reminders over WhatsApp. Gated by INTERNAL_SERVICE_KEY.
// GET /api/v1/s2s/{tenant}/billing-contact
func (h *AdminHandler) S2STenantBillingContact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := h.tenantByRef(ctx, strings.TrimSpace(chi.URLParam(r, "tenant")))
	if ent.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
		return
	}
	if err != nil {
		h.logger.Error("S2S billing contact: resolve tenant", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not resolve tenant", nil)
		return
	}

	members, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.TenantID(t.ID), tenantmembership.StatusEQ("active")).
		Order(ent.Asc(tenantmembership.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		h.logger.Error("S2S billing contact: memberships", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not load members", nil)
		return
	}
	ids := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		if isBillingAdminRole(m.Roles) {
			ids = append(ids, m.UserID)
		}
	}
	users := map[uuid.UUID]*ent.User{}
	if len(ids) > 0 {
		list, uerr := h.ent.User.Query().Where(user.IDIn(ids...)).WithPhones().All(ctx)
		if uerr != nil {
			h.logger.Error("S2S billing contact: users", zap.Error(uerr))
			writeError(w, http.StatusInternalServerError, "server_error", "could not load members", nil)
			return
		}
		for _, u := range list {
			users[u.ID] = u
		}
	}
	admins := make([]billingContactAdmin, 0, len(ids))
	for _, m := range members {
		u, ok := users[m.UserID]
		if !ok {
			continue
		}
		a := billingContactAdmin{Roles: m.Roles, Email: u.Email}
		for _, p := range u.Edges.Phones {
			if p.IsPrimary || (a.PrimaryPhone == "" && p.IsVerified) {
				a.PrimaryPhone = p.Phone
			}
		}
		if a.PrimaryPhone == "" && len(u.Edges.Phones) > 0 {
			a.PrimaryPhone = u.Edges.Phones[0].Phone
		}
		if v, _ := u.Profile["phone"].(string); v != "" {
			a.ProfilePhone = v
		}
		admins = append(admins, a)
	}

	hqPhone := ""
	if hq, oerr := h.ent.Outlet.Query().
		Where(outlet.TenantID(t.ID), outlet.IsHq(true)).
		Order(ent.Asc(outlet.FieldCreatedAt)).
		First(ctx); oerr == nil {
		hqPhone = outletContactPhone(hq.Metadata)
	}
	tenantPhone := ""
	if t.ContactPhone != nil {
		tenantPhone = *t.ContactPhone
	}

	phone, source := pickBillingPhone(admins, hqPhone, tenantPhone)
	writeJSON(w, http.StatusOK, map[string]string{"phone": phone, "source": source})
}
