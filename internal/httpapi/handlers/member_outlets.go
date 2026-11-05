package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	entoutlet "github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
)

// multiOutletRoles may work several outlets or the whole tenant. Every other staff role works one
// outlet. A member holding several roles gets the widest, and an admin is always tenant-wide.
var multiOutletRoles = map[string]bool{"manager": true, "accountant": true, "warehouse_manager": true}

func holdsMultiOutletRole(roles []string) bool {
	for _, r := range roles {
		if multiOutletRoles[r] {
			return true
		}
	}
	return false
}

var (
	errOutletsAdminTenantWide = errors.New("an admin works across the whole organisation")
	errOutletsSingleRole      = errors.New("this role works one outlet only; several outlets need the Manager, Accountant or Warehouse Manager role")
)

// resolveMemberOutlets applies the rule above to a member's new roles. requested is what the admin
// asked for (nil = no change). limit is the list to store and home is set when a floor role's one
// outlet should become its home outlet. changed is false when the stored list stays as it is.
func resolveMemberOutlets(roles, current []string, requested *[]string) (limit []string, home string, changed bool, err error) {
	switch {
	case hasTenantAdminRole(roles):
		if requested != nil && len(*requested) > 0 {
			return nil, "", false, errOutletsAdminTenantWide
		}
		return nil, "", len(current) > 0, nil
	case !holdsMultiOutletRole(roles):
		if requested != nil {
			if len(*requested) > 1 {
				return nil, "", false, errOutletsSingleRole
			}
			if len(*requested) == 1 {
				home = (*requested)[0]
			}
		} else if len(current) > 0 {
			home = current[0] // lost the management role: stays on their first outlet
		}
		return nil, home, len(current) > 0 || home != "", nil
	case requested == nil:
		return current, "", false, nil
	}
	seen := map[string]bool{}
	limit = make([]string, 0, len(*requested))
	for _, id := range *requested {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" && !seen[id] {
			seen[id] = true
			limit = append(limit, id)
		}
	}
	return limit, "", true, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// outletsActiveInTenant reports whether every id is an active outlet of the tenant.
func (h *AdminHandler) outletsActiveInTenant(ctx context.Context, tenantID uuid.UUID, ids []string) (bool, error) {
	parsed := make([]uuid.UUID, 0, len(ids))
	for _, s := range ids {
		id, err := uuid.Parse(s)
		if err != nil {
			return false, nil
		}
		parsed = append(parsed, id)
	}
	n, err := h.ent.Outlet.Query().
		Where(entoutlet.IDIn(parsed...), entoutlet.TenantID(tenantID), entoutlet.Status("active")).
		Count(ctx)
	return n == len(parsed), err
}

// S2SMemberOutletLimit answers which outlets a member is limited to, for a service that signs its
// own sessions (POS and inventory PIN logins). An empty list means no limit.
// GET /api/v1/s2s/tenants/{tenant_id}/members/{user_id}/outlet-limit
func (h *AdminHandler) S2SMemberOutletLimit(w http.ResponseWriter, r *http.Request) {
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}
	m, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.TenantID(tenantID), tenantmembership.UserID(userID)).
		Only(r.Context())
	if ent.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "member not found", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not read member", nil)
		return
	}
	limit := m.OutletIds
	if limit == nil || hasTenantAdminRole(m.Roles) {
		limit = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"outlet_ids": limit})
}
