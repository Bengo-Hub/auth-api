// Package access decides which services a tenant member gets: the services each downstream
// service keeps a local copy of the user for, carried as `services` on auth.user events and as the
// `user_services` token claim.
//
// Rules (user decision, 2026-11-03):
//   - A platform admin gets every service ("*").
//   - A tenant admin (superuser, admin) gets every service the tenant's plan entitles it to; in a
//     tenant no plan gates (platform owner, demo, subscription exempt, pay-per-transaction) that is
//     every service. Other members of such a tenant still follow the rules below.
//   - Any other member gets the services assigned to them (TenantMembership.services), within the
//     plan. A tenant admin's assignment is checked for a role per service when made
//     (UnbackedServices); a service adding a member for itself grants itself.
//   - A member nobody assigned yet follows their roles: a role scoped to a service, and the
//     services its permissions cover in auth. A member holding a cross-service job role
//     (manager, staff, viewer, accountant, ...) or a role auth does not know keeps every entitled
//     service until an admin assigns, so nobody loses access by default.
//
// Every lookup failure answers "unknown" (ok=false), never an empty list: callers then omit the
// services, and downstream services keep their previous behaviour instead of removing users.
package access

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/permission"
	"github.com/bengobox/auth-api/internal/ent/role"
	"github.com/bengobox/auth-api/internal/ent/rolepermission"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
)

// All is the service list meaning every service.
const All = "*"

const platformTenantSlug = "codevertex"

// adminRoles are the tenant admin roles: every entitled service, and no role needed per service.
var adminRoles = map[string]bool{"superuser": true, "admin": true, "superusers": true}

// customerRoles are platform-scoped roles for people the tenant serves, not staff: they never
// count as a cross-service job role.
var customerRoles = map[string]bool{"customer": true, "member": true}

// Entitlement is a tenant's plan as far as services go.
type Entitlement struct {
	// Tags are the plan's service tags (pos, inventory, ...).
	Tags []string
	// All means the tenant is not gated by a plan (no subscription needed).
	All bool
}

// EntitlementFunc reads the tenant's entitled service tags from subscription-service.
// tags=nil with err=nil means the tenant has no subscription.
type EntitlementFunc func(ctx context.Context, tenantID uuid.UUID) (tags []string, billingMode string, err error)

// Resolver computes members' services. Safe for concurrent use.
type Resolver struct {
	client      *ent.Client
	entitlement EntitlementFunc

	mu        sync.Mutex
	plans     map[uuid.UUID]cachedPlan
	roles     map[string]roleInfo
	rolesExp  time.Time
	admins    map[uuid.UUID]bool
	adminsExp time.Time
	cacheTTL  time.Duration
	nowFunc   func() time.Time
}

type cachedPlan struct {
	plan Entitlement
	exp  time.Time
}

// roleInfo is what auth knows about a role: its scope and the services its permissions cover.
type roleInfo struct {
	scope    string
	services map[string]bool
}

// New returns a resolver. entitlement may be nil (subscriptions disabled): every tenant is then
// treated as not gated by a plan.
func New(client *ent.Client, entitlement EntitlementFunc) *Resolver {
	return &Resolver{
		client:      client,
		entitlement: entitlement,
		plans:       map[uuid.UUID]cachedPlan{},
		cacheTTL:    time.Minute,
		nowFunc:     time.Now,
	}
}

// MemberServices returns the services of the member userID in tenantID, sorted, or [All].
// ok=false means it could not be decided (no membership, or a lookup failed).
func (r *Resolver) MemberServices(ctx context.Context, tenantID, userID uuid.UUID) (services []string, ok bool) {
	if r == nil || tenantID == uuid.Nil || userID == uuid.Nil {
		return nil, false
	}
	m, err := r.client.TenantMembership.Query().
		Where(tenantmembership.TenantID(tenantID), tenantmembership.UserID(userID)).
		Only(ctx)
	if err != nil {
		return nil, false
	}
	return r.ForMembership(ctx, m)
}

// ForMembership is MemberServices for an already loaded membership. The plan, the role catalogue
// and the platform admins are cached, so a list of members costs no query per member.
func (r *Resolver) ForMembership(ctx context.Context, m *ent.TenantMembership) (services []string, ok bool) {
	if r == nil || m == nil {
		return nil, false
	}
	admins, err := r.platformAdmins(ctx)
	if err != nil {
		return nil, false
	}
	if admins[m.UserID] {
		return []string{All}, true
	}
	plan, err := r.Plan(ctx, m.TenantID)
	if err != nil || (!plan.All && plan.Tags == nil) {
		// No subscription at all: the tenant-level plan gates already refuse it, so answer
		// unknown rather than an empty list that would remove the member everywhere.
		return nil, false
	}
	roles, err := r.roleInfos(ctx)
	if err != nil {
		return nil, false
	}
	return effective(m.Roles, m.Services, plan, roles), true
}

// Allows reports whether a service list (MemberServices) includes service.
func Allows(services []string, service string) bool {
	for _, s := range services {
		if s == All || s == service {
			return true
		}
	}
	return false
}

// effective applies the rules to one membership.
func effective(memberRoles, assigned []string, plan Entitlement, roles map[string]roleInfo) []string {
	if hasAdminRole(memberRoles) {
		if plan.All {
			return []string{All}
		}
		return normalize(plan.Tags)
	}
	var want []string
	if assigned != nil {
		want = assigned
	}
	backed, everything := roleServices(memberRoles, roles, assigned == nil)
	switch {
	case assigned != nil:
	case everything:
		if plan.All {
			return []string{All}
		}
		return normalize(plan.Tags)
	default:
		for s := range backed {
			want = append(want, s)
		}
	}
	if plan.All {
		return normalize(want)
	}
	inPlan := make(map[string]bool, len(plan.Tags))
	for _, t := range plan.Tags {
		inPlan[t] = true
	}
	var out []string
	for _, s := range want {
		if inPlan[s] {
			out = append(out, s)
		}
	}
	return normalize(out)
}

// roleServices returns the services the member's roles cover by scope or permission. With
// derived=true (nothing assigned yet), a cross-service job role or a role auth does not know
// answers everything=true: the member keeps every entitled service.
func roleServices(memberRoles []string, roles map[string]roleInfo, derived bool) (map[string]bool, bool) {
	out := map[string]bool{}
	everything := false
	for _, code := range memberRoles {
		info, known := roles[code]
		if !known {
			if derived {
				everything = true
			}
			continue
		}
		if isJobRole(code, info) && derived {
			everything = true
		}
		if info.scope != "" && info.scope != "platform" {
			out[info.scope] = true
		}
		for s := range info.services {
			out[s] = true
		}
	}
	return out, everything
}

// roleBacks reports whether one of the member's roles belongs to service: scoped to it, granting
// its permissions, or a cross-service job role (a manager can work in any service).
func roleBacks(memberRoles []string, roles map[string]roleInfo, service string) bool {
	for _, code := range memberRoles {
		if adminRoles[code] {
			return true
		}
		info, known := roles[code]
		if !known {
			continue
		}
		if info.scope == service || info.services[service] || isJobRole(code, info) {
			return true
		}
	}
	return false
}

// isJobRole reports a platform-scoped staff role that spans services (manager, staff, viewer,
// accountant, ...), as opposed to a customer role or a role scoped to one service.
func isJobRole(code string, info roleInfo) bool {
	return (info.scope == "platform" || info.scope == "") && !customerRoles[code]
}

func hasAdminRole(memberRoles []string) bool {
	for _, r := range memberRoles {
		if adminRoles[r] {
			return true
		}
	}
	return false
}

// RolesForService lists the roles auth knows that belong to service (scoped to it or granting its
// permissions), for prompting an admin who assigns a service the member has no role for.
func (r *Resolver) RolesForService(ctx context.Context, service string) ([]string, error) {
	roles, err := r.roleInfos(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for code, info := range roles {
		if info.scope == service || info.services[service] {
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out, nil
}

// UnbackedServices returns the requested services none of memberRoles belongs to. A tenant admin
// needs no role per service.
func (r *Resolver) UnbackedServices(ctx context.Context, memberRoles, services []string) ([]string, error) {
	if hasAdminRole(memberRoles) {
		return nil, nil
	}
	roles, err := r.roleInfos(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range services {
		if !roleBacks(memberRoles, roles, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// Plan returns the tenant's service entitlement, cached for a minute.
func (r *Resolver) Plan(ctx context.Context, tenantID uuid.UUID) (Entitlement, error) {
	now := r.nowFunc()
	r.mu.Lock()
	if c, ok := r.plans[tenantID]; ok && now.Before(c.exp) {
		r.mu.Unlock()
		return c.plan, nil
	}
	r.mu.Unlock()

	t, err := r.client.Tenant.Query().Where(tenant.ID(tenantID)).Only(ctx)
	if err != nil {
		return Entitlement{}, fmt.Errorf("load tenant: %w", err)
	}
	plan := Entitlement{All: exemptTenant(t)}
	if !plan.All && r.entitlement != nil {
		tags, billingMode, err := r.entitlement(ctx, tenantID)
		if err != nil {
			return Entitlement{}, err
		}
		if billingMode == "service_charge" {
			plan.All = true
		}
		plan.Tags = tags
	} else if r.entitlement == nil {
		plan.All = true
	}
	r.mu.Lock()
	r.plans[tenantID] = cachedPlan{plan: plan, exp: now.Add(r.cacheTTL)}
	r.mu.Unlock()
	return plan, nil
}

// exemptTenant mirrors the token minting rules: the platform tenant, demo tenants and tenants the
// platform marked exempt are never gated by a plan.
func exemptTenant(t *ent.Tenant) bool {
	if t.Slug == platformTenantSlug || t.Slug == "codevertex-demo" || t.SubscriptionExempt {
		return true
	}
	for _, key := range []string{"is_platform_owner", "is_demo"} {
		if v, ok := t.Metadata[key].(bool); ok && v {
			return true
		}
	}
	if v, ok := t.Metadata["billing_mode"].(string); ok && v == "service_charge" {
		return true
	}
	return false
}

// platformAdmins lists the users holding an admin-tier role (superuser, admin) in the platform
// tenant, the rule Service.IsPlatformOwner uses, cached for a minute.
func (r *Resolver) platformAdmins(ctx context.Context) (map[uuid.UUID]bool, error) {
	now := r.nowFunc()
	r.mu.Lock()
	if r.admins != nil && now.Before(r.adminsExp) {
		defer r.mu.Unlock()
		return r.admins, nil
	}
	r.mu.Unlock()
	ms, err := r.client.TenantMembership.Query().
		Where(tenantmembership.HasTenantWith(tenant.SlugEQ(platformTenantSlug))).
		Select(tenantmembership.FieldUserID, tenantmembership.FieldRoles).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load platform admins: %w", err)
	}
	out := make(map[uuid.UUID]bool, len(ms))
	for _, m := range ms {
		for _, role := range m.Roles {
			if role == "superuser" || role == "admin" {
				out[m.UserID] = true
			}
		}
	}
	r.mu.Lock()
	r.admins, r.adminsExp = out, now.Add(r.cacheTTL)
	r.mu.Unlock()
	return out, nil
}

// roleInfos loads every role's scope and permission services, cached for a minute.
func (r *Resolver) roleInfos(ctx context.Context) (map[string]roleInfo, error) {
	now := r.nowFunc()
	r.mu.Lock()
	if r.roles != nil && now.Before(r.rolesExp) {
		defer r.mu.Unlock()
		return r.roles, nil
	}
	r.mu.Unlock()

	rs, err := r.client.Role.Query().Select(role.FieldRoleCode, role.FieldScope).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load roles: %w", err)
	}
	out := make(map[string]roleInfo, len(rs))
	for _, ro := range rs {
		out[ro.RoleCode] = roleInfo{scope: strings.TrimSpace(ro.Scope), services: map[string]bool{}}
	}
	rps, err := r.client.RolePermission.Query().WithPermission(func(q *ent.PermissionQuery) {
		q.Select(permission.FieldCode)
	}).Select(rolepermission.FieldRoleName, rolepermission.FieldPermissionID).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load role permissions: %w", err)
	}
	for _, rp := range rps {
		if rp.Edges.Permission == nil {
			continue
		}
		svc, _, _ := strings.Cut(rp.Edges.Permission.Code, ".")
		if svc == "" || svc == "auth" {
			continue // every role signs in; that says nothing about other services
		}
		info, ok := out[rp.RoleName]
		if !ok {
			info = roleInfo{services: map[string]bool{}}
			out[rp.RoleName] = info
		}
		info.services[svc] = true
	}
	r.mu.Lock()
	r.roles, r.rolesExp = out, now.Add(r.cacheTTL)
	r.mu.Unlock()
	return out, nil
}

// normalize de-duplicates and sorts a service list; the result is never nil.
func normalize(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
