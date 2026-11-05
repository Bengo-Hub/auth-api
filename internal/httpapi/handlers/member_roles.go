package handlers

import (
	"context"
	"net/http"
	"strings"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	entoutlet "github.com/bengobox/auth-api/internal/ent/outlet"
	entrole "github.com/bengobox/auth-api/internal/ent/role"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
)

// maxAdminsLimit is the plan limit on a tenant's admins (seeded on every PowerSuite tier).
const maxAdminsLimit = "max_admins"

// superRoles are never granted by a tenant admin. A member who already holds one keeps it.
var superRoles = map[string]bool{"superuser": true, "superusers": true}

// platformOnlyRoles are not staff roles a tenant admin hands out: developer opens the developer
// portal, and member and customer are people the tenant serves, who join through sign-up. The
// platform team and services adding their own members can still use them.
var platformOnlyRoles = map[string]bool{"developer": true, "member": true, "customer": true}

func isTenantAdminRole(role string) bool { return role == "admin" || superRoles[role] }

func hasTenantAdminRole(roles []string) bool {
	for _, r := range roles {
		if isTenantAdminRole(r) {
			return true
		}
	}
	return false
}

// refusedRoles lists the requested roles a tenant admin may not grant: a super or platform-only role,
// or a code auth does not know. Roles the member already holds always pass, because services keep roles of their
// own that auth's catalogue never lists and an edit must not strip them.
func refusedRoles(requested, existing []string, known map[string]bool) []string {
	held := make(map[string]bool, len(existing))
	for _, r := range existing {
		held[r] = true
	}
	var refused []string
	for _, r := range requested {
		if held[r] {
			continue
		}
		if superRoles[r] || platformOnlyRoles[r] || !known[r] {
			refused = append(refused, r)
		}
	}
	return refused
}

// isStaffAddFromAccounts reports a person adding a staff member in Accounts. A service adding its own
// member comes in with no user on its claims, and customers are not tied to a branch.
func (h *AdminHandler) isStaffAddFromAccounts(r *http.Request, roles []string) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	return ok && claims != nil && claims.Subject != "" && hasStaffRole(roles)
}

// hasStaffRole reports a role other than the customer ones.
func hasStaffRole(roles []string) bool {
	for _, role := range roles {
		if role != "customer" && role != "member" {
			return true
		}
	}
	return false
}

// defaultOutletID is where a new staff member goes when nobody picked an outlet: the tenant's HQ,
// else its oldest active outlet. Nil when it has none, or the lookup fails: adding the member matters
// more than placing them, and an admin can still assign the outlet afterwards.
func (h *AdminHandler) defaultOutletID(ctx context.Context, tenantID uuid.UUID) *uuid.UUID {
	row, err := h.ent.Outlet.Query().
		Where(entoutlet.TenantID(tenantID), entoutlet.StatusEQ("active")).
		Order(ent.Desc(entoutlet.FieldIsHq), ent.Asc(entoutlet.FieldCreatedAt)).
		First(ctx)
	if err != nil {
		if !ent.IsNotFound(err) {
			h.logger.Warn("default outlet lookup failed", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		}
		return nil
	}
	return &row.ID
}

// isPlatformActor reports a platform owner or an admin-scoped service token: they may grant any
// role, including a service's own, and may leave a tenant without an admin to repair it.
func isPlatformActor(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}
	if claims.IsPlatformOwner {
		return true
	}
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// countActiveTenantAdmins counts the tenant's active admins, leaving out exclude.
func (h *AdminHandler) countActiveTenantAdmins(ctx context.Context, tenantID, exclude uuid.UUID) (int, error) {
	return h.ent.TenantMembership.Query().
		Where(
			tenantmembership.TenantID(tenantID),
			tenantmembership.StatusEQ("active"),
			tenantmembership.UserIDNEQ(exclude),
			func(s *sql.Selector) {
				s.Where(sql.Or(
					sqljson.ValueContains(tenantmembership.FieldRoles, "admin"),
					sqljson.ValueContains(tenantmembership.FieldRoles, "superuser"),
					sqljson.ValueContains(tenantmembership.FieldRoles, "superusers"),
				))
			},
		).Count(ctx)
}

// checkGrantableRoles refuses roles a tenant admin may not grant. It answers true after writing the
// refusal.
func (h *AdminHandler) checkGrantableRoles(w http.ResponseWriter, r *http.Request, requested, existing []string) bool {
	if len(requested) == 0 || isPlatformActor(r) {
		return false
	}
	rows, err := h.ent.Role.Query().Where(entrole.RoleCodeIn(requested...)).Select(entrole.FieldRoleCode).All(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "roles_unavailable", "Roles could not be read; try again shortly.", nil)
		return true
	}
	known := make(map[string]bool, len(rows))
	for _, row := range rows {
		known[row.RoleCode] = true
	}
	if refused := refusedRoles(requested, existing, known); len(refused) > 0 {
		writeError(w, http.StatusUnprocessableEntity, "role_not_allowed",
			"These roles cannot be assigned: "+strings.Join(refused, ", ")+".", map[string]any{"roles": refused})
		return true
	}
	return false
}

// checkAdminLimit refuses a new admin beyond the plan's max_admins, read from the caller's token.
// With no limit in the token (an exempt tenant, or a plan without one) there is nothing to enforce.
// It answers true after writing the refusal.
func (h *AdminHandler) checkAdminLimit(w http.ResponseWriter, r *http.Request, tenantID, userID uuid.UUID, current, requested []string) bool {
	if isPlatformActor(r) || hasTenantAdminRole(current) || !hasTenantAdminRole(requested) {
		return false
	}
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}
	limit := claims.SubscriptionLimits[maxAdminsLimit]
	if limit <= 0 {
		return false
	}
	count, err := h.countActiveTenantAdmins(r.Context(), tenantID, userID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "members_unavailable", "Team members could not be read; try again shortly.", nil)
		return true
	}
	if count >= limit {
		writeError(w, http.StatusUnprocessableEntity, "admin_limit_reached",
			"Your plan allows a limited number of admins. Change an existing admin's role or upgrade your plan.",
			map[string]any{"limit": limit, "used": count})
		return true
	}
	return false
}

// checkKeepsAnAdmin stops a change that takes admin rights away when it would lock the tenant out:
// an admin removing their own rights, or the tenant's last active admin going. It answers true after
// writing the refusal.
func (h *AdminHandler) checkKeepsAnAdmin(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, member *ent.TenantMembership) bool {
	if isPlatformActor(r) || member.Status != "active" || !hasTenantAdminRole(member.Roles) {
		return false
	}
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims != nil && claims.Subject == member.UserID.String() {
		writeError(w, http.StatusConflict, "cannot_change_own_admin", "Ask another admin to change your own admin access.", nil)
		return true
	}
	others, err := h.countActiveTenantAdmins(r.Context(), tenantID, member.UserID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "members_unavailable", "Team members could not be read; try again shortly.", nil)
		return true
	}
	if others == 0 {
		writeError(w, http.StatusConflict, "last_admin", "This is your organisation's only active admin. Make someone else an admin first.", nil)
		return true
	}
	return false
}
