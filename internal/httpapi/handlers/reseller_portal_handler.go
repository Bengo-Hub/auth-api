package handlers

import (
	"net/http"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/resellerapplication"
	enttenant "github.com/bengobox/auth-api/internal/ent/tenant"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ResellerPortalHandler exposes the read-only, tenant-JWT-gated self-service surface a
// certified reseller uses to see their own status/clients/commission — as distinct from
// ResellerHandler (the applicant-facing apply endpoint + platform-admin approval queue) and
// treasury-api's platform-owner-gated equity/referral admin surface.
//
// Scoped to Sub-model B ("Commission Partner") only for now, per the confirmed B-before-A
// sequencing decision (.claude/plans/reseller-partner-program-plan-2026-08-23.md §12) — there
// is deliberately no price-declaration endpoint here yet (that's Sub-model A, Phase 4).
// See the plan's register item G9 for why this handler exists: §8's original "portal
// capabilities" list never specified this API surface, and nothing built in Phase 1/2 was
// reachable by a reseller's own tenant JWT.
type ResellerPortalHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

func NewResellerPortalHandler(entClient *ent.Client, logger *zap.Logger) *ResellerPortalHandler {
	return &ResellerPortalHandler{ent: entClient, logger: logger.Named("reseller_portal")}
}

// resolveOwnResellerTenant loads the caller's own Tenant from their JWT and confirms it's a
// certified reseller. Shared by every handler below so the 401/403/404 shape is consistent.
func (h *ResellerPortalHandler) resolveOwnResellerTenant(w http.ResponseWriter, r *http.Request) (*ent.Tenant, bool) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims.TenantID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return nil, false
	}
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid tenant context", nil)
		return nil, false
	}
	tenant, err := h.ent.Tenant.Get(r.Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
			return nil, false
		}
		h.logger.Error("failed to load own tenant for reseller portal", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load tenant", nil)
		return nil, false
	}
	if !tenant.IsReseller {
		writeError(w, http.StatusForbidden, "not_a_reseller", "this organisation is not a certified reseller partner", nil)
		return nil, false
	}
	return tenant, true
}

// GetOwnStatus returns the caller's own reseller status/tier — tier and KYB/agreement details
// come from their own most recent approved ResellerApplication, when one is linked; a reseller
// tenant created by an earlier flow with no traceable application still returns a minimal
// is_reseller=true response rather than 404ing (tenant.is_reseller is the source of truth).
// GET /api/v1/reseller/me
func (h *ResellerPortalHandler) GetOwnStatus(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.resolveOwnResellerTenant(w, r)
	if !ok {
		return
	}

	resp := map[string]any{
		"tenant_id":   tenant.ID.String(),
		"is_reseller": true,
	}

	app, err := h.ent.ResellerApplication.Query().
		Where(
			resellerapplication.TenantIDEQ(tenant.ID),
			resellerapplication.StatusEQ(resellerapplication.StatusApproved),
		).
		Order(ent.Desc(resellerapplication.FieldUpdatedAt)).
		First(r.Context())
	if err != nil && !ent.IsNotFound(err) {
		h.logger.Warn("failed to load reseller application for own-status lookup", zap.Error(err))
	}
	if app != nil {
		resp["requested_tier"] = string(app.RequestedTier)
		resp["business_name"] = app.BusinessName
		resp["application_id"] = app.ID.String()
		if app.AgreementAcceptanceID != nil {
			resp["agreement_acceptance_id"] = app.AgreementAcceptanceID.String()
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetOwnClients lists the tenants this reseller is the commercial channel of record for
// (Tenant.managed_by_reseller_tenant_id == caller's own tenant id) — the commercial/billing
// scope only, per the plan's §6A access-boundary rule: this grants no visibility whatsoever
// into any of these tenants' own operational data (POS sales, inventory, financials).
// GET /api/v1/reseller/clients
func (h *ResellerPortalHandler) GetOwnClients(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.resolveOwnResellerTenant(w, r)
	if !ok {
		return
	}

	clients, err := h.ent.Tenant.Query().
		Where(enttenant.ManagedByResellerTenantIDEQ(tenant.ID)).
		Order(ent.Desc(enttenant.FieldCreatedAt)).
		All(r.Context())
	if err != nil {
		h.logger.Error("failed to list reseller's own clients", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list clients", nil)
		return
	}

	resp := make([]map[string]any, 0, len(clients))
	for _, c := range clients {
		row := map[string]any{
			"id":         c.ID.String(),
			"name":       c.Name,
			"slug":       c.Slug,
			"status":     c.Status,
			"created_at": c.CreatedAt,
		}
		if c.ContactEmail != nil {
			row["contact_email"] = *c.ContactEmail
		}
		resp = append(resp, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": resp})
}
