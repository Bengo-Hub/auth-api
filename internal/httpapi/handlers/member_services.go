package handlers

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/services/access"
)

// memberServicesError is an assignment the tenant admin must change, answered with 422.
type memberServicesError struct {
	code    string
	message string
	details map[string]any
}

// checkMemberServices validates services a tenant admin assigns to a member holding roles: each
// must be in the tenant's plan, and backed by one of the roles (a cashier-only member assigned
// inventory needs an inventory role first). Returns the cleaned list. A tenant admin role needs no
// role per service; a plan lookup failure refuses the change rather than guessing.
func (h *AdminHandler) checkMemberServices(ctx context.Context, tenantID uuid.UUID, roles, services []string) ([]string, *memberServicesError) {
	clean := make([]string, 0, len(services))
	seen := map[string]bool{}
	for _, s := range services {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || s == access.All || seen[s] {
			continue
		}
		seen[s] = true
		clean = append(clean, s)
	}
	sort.Strings(clean)
	if h.access == nil {
		return clean, nil
	}
	plan, err := h.access.Plan(ctx, tenantID)
	if err != nil {
		return nil, &memberServicesError{"plan_unavailable", "The organisation's plan could not be read; try again shortly.", nil}
	}
	if !plan.All {
		inPlan := map[string]bool{}
		for _, t := range plan.Tags {
			inPlan[t] = true
		}
		var outside []string
		for _, s := range clean {
			if !inPlan[s] {
				outside = append(outside, s)
			}
		}
		if len(outside) > 0 {
			return nil, &memberServicesError{"service_not_in_plan",
				"Your plan does not include: " + strings.Join(outside, ", ") + ".",
				map[string]any{"services": outside}}
		}
	}
	unbacked, err := h.access.UnbackedServices(ctx, roles, clean)
	if err != nil {
		return nil, &memberServicesError{"roles_unavailable", "Roles could not be read; try again shortly.", nil}
	}
	if len(unbacked) > 0 {
		suggest := map[string][]string{}
		for _, s := range unbacked {
			rs, _ := h.access.RolesForService(ctx, s)
			suggest[s] = rs
		}
		return nil, &memberServicesError{"role_required_for_service",
			"Add a role for " + strings.Join(unbacked, ", ") + " before giving access to it.",
			map[string]any{"services": unbacked, "roles_by_service": suggest}}
	}
	return clean, nil
}

func writeMemberServicesError(w http.ResponseWriter, e *memberServicesError) {
	status := http.StatusUnprocessableEntity
	if e.code == "plan_unavailable" || e.code == "roles_unavailable" {
		status = http.StatusServiceUnavailable
	}
	writeError(w, status, e.code, e.message, e.details)
}

// effectiveMemberServices is the member's services for responses; nil when unknown.
func (h *AdminHandler) effectiveMemberServices(ctx context.Context, m *ent.TenantMembership) []string {
	if h.access == nil {
		return nil
	}
	services, ok := h.access.ForMembership(ctx, m)
	if !ok {
		return nil
	}
	return services
}

// grantMemberService makes sure a member keeps service: when a service adds a member for itself,
// the member works there. The calling service is the authority on its own roles (many are not in
// auth's catalogue), so no role check, but the plan still bounds it. A member whose services
// already include it is left as is (an unassigned member keeps following their roles); otherwise
// the member's current services plus this one become their assignment. Failures keep m unchanged.
func (h *AdminHandler) grantMemberService(ctx context.Context, m *ent.TenantMembership, service string) *ent.TenantMembership {
	if h.access == nil || service == "" {
		return m
	}
	current, ok := h.access.ForMembership(ctx, m)
	if !ok || access.Allows(current, service) {
		return m
	}
	plan, err := h.access.Plan(ctx, m.TenantID)
	if err != nil || (!plan.All && !access.Allows(plan.Tags, service)) {
		return m
	}
	updated, err := m.Update().SetServices(normalizeServices(append(append([]string{}, current...), service))).Save(ctx)
	if err != nil {
		h.logger.Warn("grant member service failed", zap.String("service", service), zap.Error(err))
		return m
	}
	return updated
}

func normalizeServices(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || s == access.All || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
