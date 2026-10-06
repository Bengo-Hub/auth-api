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

// billingPhone is one place a tenant's bills can go by phone.
type billingPhone struct {
	Phone  string `json:"phone"`
	Source string `json:"source"` // tenant_admin, main_outlet or tenant
}

// pickBillingPhones is the one rule for where a tenant's bills go by phone, in order: the first
// tenant administrator with a phone (their primary phone, else the profile phone), then the head
// office outlet's phone, then the tenant's own contact phone. One number per step, and a number
// already listed is not repeated. A message goes to the first; the rest are its backups.
func pickBillingPhones(admins []billingContactAdmin, hqPhone, tenantPhone string) []billingPhone {
	out := []billingPhone{}
	seen := map[string]bool{}
	add := func(p, source string) bool {
		p = strings.TrimSpace(p)
		if p == "" {
			return false
		}
		if key := subscriberDigits(p); !seen[key] {
			seen[key] = true
			out = append(out, billingPhone{Phone: p, Source: source})
		}
		return true
	}
	for _, a := range admins {
		if !isBillingAdminRole(a.Roles) {
			continue
		}
		if add(a.PrimaryPhone, "tenant_admin") || add(a.ProfilePhone, "tenant_admin") {
			break
		}
	}
	add(hqPhone, "main_outlet")
	add(tenantPhone, "tenant")
	return out
}

// subscriberDigits is the last nine digits, so "0745..." and "+254745..." count as one number.
func subscriberDigits(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	d := b.String()
	if len(d) > 9 {
		return d[len(d)-9:]
	}
	return d
}

// S2STenantBillingContact answers where a tenant's billing messages go by phone (see
// pickBillingPhones): phone/source is the first, phones the whole ordered list. notifications-api uses it to send subscription invoices and payment
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

	phones := pickBillingPhones(admins, hqPhone, tenantPhone)
	resp := map[string]any{"phone": "", "source": "", "phones": phones}
	if len(phones) > 0 {
		resp["phone"], resp["source"] = phones[0].Phone, phones[0].Source
	}
	writeJSON(w, http.StatusOK, resp)
}
