package handlers

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/ent/predicate"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useremail"
)

// reachAddress is one way to reach a tenant or a person, in the order to try it.
type reachAddress struct {
	Address   string `json:"address"`
	Source    string `json:"source"` // owner, admin, staff, tenant, main_outlet
	Verified  bool   `json:"verified"`
	FirstName string `json:"first_name,omitempty"`
}

// reachEntry is one recipient for a broadcast: a tenant (purpose=broadcast) or one of its staff
// (purpose=staff).
type reachEntry struct {
	Key          string         `json:"key"`
	TenantID     string         `json:"tenant_id"`
	Slug         string         `json:"slug"`
	BusinessName string         `json:"business_name"`
	Name         string         `json:"name,omitempty"`
	Country      string         `json:"country"`
	Timezone     string         `json:"timezone"`
	Emails       []reachAddress `json:"emails"`
	Phones       []reachAddress `json:"phones"`
}

// reachPerson is a member's verified contacts and how to greet them.
type reachPerson struct {
	userID    uuid.UUID
	firstName string
	fullName  string
	owner     bool
	emails    []string // verified, primary first
	phones    []string // verified, primary first
}

// firstNameOf reads a user's first name from the profile (first_name, else the first word of name
// or full_name).
func firstNameOf(profile map[string]any) (first, full string) {
	for _, k := range []string{"name", "full_name"} {
		if v, _ := profile[k].(string); strings.TrimSpace(v) != "" {
			full = strings.TrimSpace(v)
			break
		}
	}
	if v, _ := profile["first_name"].(string); strings.TrimSpace(v) != "" {
		first = strings.TrimSpace(v)
	} else if full != "" {
		first = strings.Fields(full)[0]
	}
	if full == "" {
		last, _ := profile["last_name"].(string)
		full = strings.TrimSpace(first + " " + last)
	}
	return first, full
}

// verifiedContacts lists a user's verified email addresses and phones, primary first. The login
// email counts when the account's email is verified.
func verifiedContacts(u *ent.User) (emails, phones []string) {
	if u.EmailVerified && strings.TrimSpace(u.Email) != "" {
		emails = append(emails, u.Email)
	}
	es := append([]*ent.UserEmail(nil), u.Edges.Emails...)
	sort.SliceStable(es, func(i, j int) bool { return es[i].IsPrimary && !es[j].IsPrimary })
	for _, e := range es {
		if e.IsVerified {
			emails = append(emails, e.Email)
		}
	}
	ps := append([]*ent.UserPhone(nil), u.Edges.Phones...)
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].IsPrimary && !ps[j].IsPrimary })
	for _, p := range ps {
		if p.IsVerified {
			phones = append(phones, p.Phone)
		}
	}
	return emails, phones
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(strings.TrimSpace(r), want) {
			return true
		}
	}
	return false
}

// outletContactEmail reads an outlet's email from metadata: contact_emails [{label, value}] (the
// outlet form) or a plain email / contact_email.
func outletContactEmail(meta map[string]any) string {
	if list, ok := meta["contact_emails"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				if v, _ := m["value"].(string); strings.Contains(v, "@") {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	for _, k := range []string{"email", "contact_email"} {
		if v, _ := meta[k].(string); strings.Contains(v, "@") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// pickBroadcastContacts is the rule for where a tenant's broadcasts (greetings, notices) go, per
// channel, in order: the owners, then the other tenant administrators, using only their verified
// addresses; then the tenant's configured contact; then the head office outlet's. A sender uses
// the first valid address and keeps the rest as backups, so a business gets one copy. Unlike
// billing (pickBillingPhones), unverified personal numbers are never used for broadcasts.
//
// Emails are only ever verified ones: a tenant or outlet contact email is used only when it is a
// verified address of some account (verifiedEmails, lower-cased). On 2026-10-08 tenant contact
// emails that were an owner's unconfirmed login were listed, then refused at send time, and the
// sender saw a vague "not sent" for most of the list.
func pickBroadcastContacts(admins []reachPerson, t *ent.Tenant, hq *ent.Outlet, verifiedEmails map[string]bool) (emails, phones []reachAddress) {
	seenEmail, seenPhone := map[string]bool{}, map[string]bool{}
	addEmail := func(v, source string, verified bool, first string) {
		v = strings.TrimSpace(v)
		k := strings.ToLower(v)
		if v == "" || seenEmail[k] {
			return
		}
		seenEmail[k] = true
		emails = append(emails, reachAddress{Address: v, Source: source, Verified: verified, FirstName: first})
	}
	addPhone := func(v, source string, verified bool, first string) {
		v = strings.TrimSpace(v)
		k := subscriberDigits(v)
		if v == "" || k == "" || seenPhone[k] {
			return
		}
		seenPhone[k] = true
		phones = append(phones, reachAddress{Address: v, Source: source, Verified: verified, FirstName: first})
	}
	ordered := append([]reachPerson(nil), admins...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].owner && !ordered[j].owner })
	for _, a := range ordered {
		source := "admin"
		if a.owner {
			source = "owner"
		}
		for _, e := range a.emails {
			addEmail(e, source, true, a.firstName)
		}
		for _, p := range a.phones {
			addPhone(p, source, true, a.firstName)
		}
	}
	addVerifiedEmail := func(v, source string) {
		if verifiedEmails[strings.ToLower(strings.TrimSpace(v))] {
			addEmail(v, source, true, "")
		}
	}
	if t.ContactEmail != nil {
		addVerifiedEmail(*t.ContactEmail, "tenant")
	}
	if t.ContactPhone != nil {
		addPhone(*t.ContactPhone, "tenant", false, "")
	}
	if hq != nil {
		addVerifiedEmail(outletContactEmail(hq.Metadata), "main_outlet")
		addPhone(outletContactPhone(hq.Metadata), "main_outlet", false, "")
	}
	return emails, phones
}

func csvParam(r *http.Request, k string) []string {
	var out []string
	for _, v := range strings.Split(r.URL.Query().Get(k), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// S2STenantsReach pages through who a broadcast reaches. Gated by INTERNAL_SERVICE_KEY.
//
//	purpose=broadcast (default): one entry per tenant (active, non-demo unless include_demo=true;
//	  filters plan, use_case, tenant_ids), contacts ordered by pickBroadcastContacts.
//	purpose=staff: one entry per active member of tenant_ids (one tenant; optional roles filter),
//	  with their verified contacts.
//
// Keyset paging: after=<last key>, limit (default 200, max 500); next is "" on the last page.
// Every page is a fixed number of queries (tenants, memberships, users with contacts, outlets).
// GET /api/v1/s2s/tenants/reach
func (h *AdminHandler) S2STenantsReach(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	after := strings.TrimSpace(r.URL.Query().Get("after"))
	if r.URL.Query().Get("purpose") == "staff" {
		h.reachStaff(w, r, after, limit)
		return
	}
	h.reachTenants(w, r, after, limit)
}

func (h *AdminHandler) reachTenants(w http.ResponseWriter, r *http.Request, after string, limit int) {
	ctx := r.Context()
	q := h.ent.Tenant.Query().Where(tenant.StatusEQ("active"))
	if r.URL.Query().Get("include_demo") != "true" {
		q = q.Where(tenant.IsDemo(false))
	}
	if plans := csvParam(r, "plan"); len(plans) > 0 {
		q = q.Where(tenant.SubscriptionPlanIn(plans...))
	}
	if ucs := csvParam(r, "use_case"); len(ucs) > 0 {
		q = q.Where(tenant.UseCaseIn(ucs...))
	}
	if ids := csvParam(r, "tenant_ids"); len(ids) > 0 {
		var uids []uuid.UUID
		for _, s := range ids {
			if id, err := uuid.Parse(s); err == nil {
				uids = append(uids, id)
			}
		}
		q = q.Where(tenant.IDIn(uids...))
	}
	if after != "" {
		if id, err := uuid.Parse(after); err == nil {
			q = q.Where(tenant.IDGT(id))
		}
	}
	tenants, err := q.Order(ent.Asc(tenant.FieldID)).Limit(limit).All(ctx)
	if err != nil {
		h.logger.Error("S2S tenants reach: tenants", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not load tenants", nil)
		return
	}
	if len(tenants) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"data": []reachEntry{}, "next": ""})
		return
	}
	ids := make([]uuid.UUID, len(tenants))
	for i, t := range tenants {
		ids[i] = t.ID
	}

	members, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.TenantIDIn(ids...), tenantmembership.StatusEQ("active")).
		Order(ent.Asc(tenantmembership.FieldCreatedAt)).All(ctx)
	if err != nil {
		h.logger.Error("S2S tenants reach: memberships", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not load members", nil)
		return
	}
	userIDs := []uuid.UUID{}
	for _, m := range members {
		if isBillingAdminRole(m.Roles) {
			userIDs = append(userIDs, m.UserID)
		}
	}
	users := map[uuid.UUID]*ent.User{}
	if len(userIDs) > 0 {
		list, err := h.ent.User.Query().Where(user.IDIn(userIDs...), user.StatusEQ("active")).WithEmails().WithPhones().All(ctx)
		if err != nil {
			h.logger.Error("S2S tenants reach: users", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "could not load members", nil)
			return
		}
		for _, u := range list {
			users[u.ID] = u
		}
	}
	admins := map[uuid.UUID][]reachPerson{}
	for _, m := range members {
		u, ok := users[m.UserID]
		if !ok || !isBillingAdminRole(m.Roles) {
			continue
		}
		first, full := firstNameOf(u.Profile)
		e, p := verifiedContacts(u)
		admins[m.TenantID] = append(admins[m.TenantID], reachPerson{userID: u.ID, firstName: first, fullName: full, owner: hasRole(m.Roles, "owner"), emails: e, phones: p})
	}

	hqs := map[uuid.UUID]*ent.Outlet{}
	outlets, err := h.ent.Outlet.Query().Where(outlet.TenantIDIn(ids...), outlet.IsHq(true)).Order(ent.Asc(outlet.FieldCreatedAt)).All(ctx)
	if err == nil {
		for _, o := range outlets {
			if _, seen := hqs[o.TenantID]; !seen {
				hqs[o.TenantID] = o
			}
		}
	}

	var contactEmails []string
	for _, t := range tenants {
		if t.ContactEmail != nil {
			contactEmails = append(contactEmails, *t.ContactEmail)
		}
		if hq := hqs[t.ID]; hq != nil {
			contactEmails = append(contactEmails, outletContactEmail(hq.Metadata))
		}
	}
	verified, err := h.verifiedEmailSet(ctx, contactEmails)
	if err != nil {
		h.logger.Error("S2S tenants reach: verified emails", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not check contact emails", nil)
		return
	}

	out := make([]reachEntry, 0, len(tenants))
	for _, t := range tenants {
		e := reachEntry{Key: t.ID.String(), TenantID: t.ID.String(), Slug: t.Slug, BusinessName: t.Name}
		if t.Country != nil {
			e.Country = *t.Country
		}
		if t.Timezone != nil {
			e.Timezone = *t.Timezone
		}
		e.Emails, e.Phones = pickBroadcastContacts(admins[t.ID], t, hqs[t.ID], verified)
		out = append(out, e)
	}
	next := ""
	if len(tenants) == limit {
		next = tenants[len(tenants)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out, "next": next})
}

// verifiedEmailSet returns which of addrs (lower-cased) are a verified address of an active
// account: a verified login email or a verified additional email. Two queries per page.
func (h *AdminHandler) verifiedEmailSet(ctx context.Context, addrs []string) (map[string]bool, error) {
	out := map[string]bool{}
	var lookup []string
	for _, a := range addrs {
		if a = strings.TrimSpace(a); a != "" {
			lookup = append(lookup, a, strings.ToLower(a))
		}
	}
	if len(lookup) == 0 {
		return out, nil
	}
	users, err := h.ent.User.Query().
		Where(user.EmailIn(lookup...), user.EmailVerified(true), user.StatusEQ("active")).
		Select(user.FieldEmail).Strings(ctx)
	if err != nil {
		return nil, err
	}
	extra, err := h.ent.UserEmail.Query().
		Where(useremail.EmailIn(lookup...), useremail.IsVerified(true)).
		Select(useremail.FieldEmail).Strings(ctx)
	if err != nil {
		return nil, err
	}
	for _, e := range append(users, extra...) {
		out[strings.ToLower(strings.TrimSpace(e))] = true
	}
	return out, nil
}

func (h *AdminHandler) reachStaff(w http.ResponseWriter, r *http.Request, after string, limit int) {
	ctx := r.Context()
	ids := csvParam(r, "tenant_ids")
	if len(ids) != 1 {
		writeError(w, http.StatusBadRequest, "bad_request", "purpose=staff needs exactly one tenant_ids value", nil)
		return
	}
	t, err := h.tenantByRef(ctx, ids[0])
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
		return
	}
	q := h.ent.TenantMembership.Query().Where(tenantmembership.TenantID(t.ID), tenantmembership.StatusEQ("active"))
	if after != "" {
		if id, err := uuid.Parse(after); err == nil {
			// user_id is an edge field, so ent generates no range predicate for it.
			q = q.Where(predicate.TenantMembership(sql.FieldGT(tenantmembership.FieldUserID, id)))
		}
	}
	members, err := q.Order(ent.Asc(tenantmembership.FieldUserID)).Limit(limit).All(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not load members", nil)
		return
	}
	roles := csvParam(r, "roles")
	userIDs := []uuid.UUID{}
	for _, m := range members {
		if hasRole(m.Roles, "superuser") || hasRole(m.Roles, "super_admin") {
			continue // platform staff on a tenant are not the tenant's staff
		}
		if len(roles) > 0 {
			match := false
			for _, want := range roles {
				if hasRole(m.Roles, want) {
					match = true
				}
			}
			if !match {
				continue
			}
		}
		userIDs = append(userIDs, m.UserID)
	}
	out := []reachEntry{}
	if len(userIDs) > 0 {
		list, err := h.ent.User.Query().Where(user.IDIn(userIDs...), user.StatusEQ("active")).WithEmails().WithPhones().All(ctx)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "could not load members", nil)
			return
		}
		sort.Slice(list, func(i, j int) bool { return list[i].ID.String() < list[j].ID.String() })
		for _, u := range list {
			first, full := firstNameOf(u.Profile)
			emails, phones := verifiedContacts(u)
			e := reachEntry{Key: u.ID.String(), TenantID: t.ID.String(), Slug: t.Slug, BusinessName: t.Name, Name: full}
			if t.Country != nil {
				e.Country = *t.Country
			}
			for _, v := range emails {
				e.Emails = append(e.Emails, reachAddress{Address: v, Source: "staff", Verified: true, FirstName: first})
			}
			for _, v := range phones {
				e.Phones = append(e.Phones, reachAddress{Address: v, Source: "staff", Verified: true, FirstName: first})
			}
			out = append(out, e)
		}
	}
	next := ""
	if len(members) == limit {
		next = members[len(members)-1].UserID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out, "next": next})
}
