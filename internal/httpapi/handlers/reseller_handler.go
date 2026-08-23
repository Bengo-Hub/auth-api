package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/resellerapplication"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/platform/outbox"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ResellerHandler handles the Certified Reseller & Partner Program's applicant→KYB→
// agreement e-sign→admin-approval state machine. Mirrors LegalHandler's
// EquityHolderApplication flow exactly, substituting a business/legal-entity applicant
// (KYB, not KYC) and a Reseller Agreement (not an EPA) — see
// .claude/plans/reseller-partner-program-plan-2026-08-23.md §6A/§7.
type ResellerHandler struct {
	ent    *ent.Client
	logger *zap.Logger
}

func NewResellerHandler(entClient *ent.Client, logger *zap.Logger) *ResellerHandler {
	return &ResellerHandler{ent: entClient, logger: logger.Named("reseller")}
}

// CreateApplication creates a reseller application.
// POST /api/v1/auth/reseller/apply
// The caller's JWT is optional (mounted behind TryAuthHandler, mirroring the exact
// optional-auth idiom CreateIntegrationRequest already uses): with a tenant JWT this is
// an EXISTING tenant applying to also become a certified reseller (tenant_id is set from
// the token); without one it's a prospective partner with no Codevertex tenant yet
// (tenant_id stays null — approval creates the Tenant, see UpdateApplication).
func (h *ResellerHandler) CreateApplication(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BusinessName           string `json:"business_name"`
		BusinessRegistrationNo string `json:"business_registration_no"`
		TaxPin                 string `json:"tax_pin"`
		ContactEmail           string `json:"contact_email"`
		ContactPhone           string `json:"contact_phone"`
		Country                string `json:"country"`
		RequestedTier          string `json:"requested_tier"`
		Notes                  string `json:"notes"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}

	req.BusinessName = strings.TrimSpace(req.BusinessName)
	req.ContactEmail = strings.TrimSpace(req.ContactEmail)
	if req.BusinessName == "" || req.ContactEmail == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "business_name and contact_email are required", nil)
		return
	}

	tier := resellerapplication.RequestedTierRegistered
	if req.RequestedTier != "" {
		tier = resellerapplication.RequestedTier(req.RequestedTier)
		if vErr := resellerapplication.RequestedTierValidator(tier); vErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_tier", "requested_tier must be registered, certified, or premier", nil)
			return
		}
	}

	create := h.ent.ResellerApplication.Create().
		SetBusinessName(req.BusinessName).
		SetContactEmail(req.ContactEmail).
		SetRequestedTier(tier).
		SetStatus(resellerapplication.StatusPending).
		SetNotes(req.Notes)
	if req.BusinessRegistrationNo != "" {
		create.SetBusinessRegistrationNo(req.BusinessRegistrationNo)
	}
	if req.TaxPin != "" {
		create.SetTaxPin(req.TaxPin)
	}
	if req.ContactPhone != "" {
		create.SetContactPhone(req.ContactPhone)
	}
	if req.Country != "" {
		create.SetCountry(req.Country)
	}
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims.TenantID != "" {
		if tid, err := uuid.Parse(claims.TenantID); err == nil {
			create.SetTenantID(tid)
		}
	}

	app, err := create.Save(r.Context())
	if err != nil {
		h.logger.Error("failed to create reseller application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create application", nil)
		return
	}
	writeJSON(w, http.StatusCreated, toResellerApplicationResponse(app))
}

// ListApplications returns reseller applications (admin only), optionally filtered by
// ?status= (mirrors ListTenants' ?status=|all pattern — omit or "all" removes the filter).
// GET /api/v1/admin/reseller/applications
func (h *ResellerHandler) ListApplications(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	// Unscoped cross-tenant read: contains every applicant's business/KYB details, so it
	// must be platform-admin only, same gate as the equity applications queue.
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	q := h.ent.ResellerApplication.Query()
	if status := r.URL.Query().Get("status"); status != "" && status != "all" {
		if vErr := resellerapplication.StatusValidator(resellerapplication.Status(status)); vErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_status", "unknown application status: "+status, nil)
			return
		}
		q = q.Where(resellerapplication.StatusEQ(resellerapplication.Status(status)))
	}

	apps, err := q.Order(ent.Desc(resellerapplication.FieldCreatedAt)).All(r.Context())
	if err != nil {
		h.logger.Error("failed to list reseller applications", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list applications", nil)
		return
	}
	resp := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		resp = append(resp, toResellerApplicationResponse(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"applications": resp})
}

// GetApplication returns a single reseller application's detail (admin only).
// GET /api/v1/admin/reseller/applications/{id}
func (h *ResellerHandler) GetApplication(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid application id", nil)
		return
	}
	app, err := h.ent.ResellerApplication.Get(r.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "application not found", nil)
			return
		}
		h.logger.Error("failed to load reseller application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load application", nil)
		return
	}
	writeJSON(w, http.StatusOK, toResellerApplicationResponse(app))
}

// UpdateApplication updates a reseller application's status/admin fields (admin only),
// enforcing the state machine's legal transitions and — on transition to approved —
// transactionally resolving the reseller Tenant (create-new-vs-link-existing) and
// emitting the outbox event, mirroring legal_handler.go's equity UpdateApplication exactly.
// PUT /api/v1/admin/reseller/applications/{id}
func (h *ResellerHandler) UpdateApplication(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
		return
	}
	// Setting status=approved emits auth.reseller_application.approved, which flips
	// Tenant.is_reseller=true (creating a new Tenant if none exists yet). Without this
	// gate any authenticated user could approve their own application and mint themselves
	// reseller status.
	if !isPlatformOrS2SAdmin(claims) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid application id", nil)
		return
	}

	var req struct {
		Status                string `json:"status"`
		Notes                 string `json:"notes"`
		KybReference          string `json:"kyb_reference"`
		KybResult             string `json:"kyb_result"`
		AgreementAcceptanceID string `json:"agreement_acceptance_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body", nil)
		return
	}

	ctx := r.Context()

	current, err := h.ent.ResellerApplication.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "application not found", nil)
			return
		}
		h.logger.Error("failed to load reseller application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	if req.Status != "" {
		if vErr := resellerapplication.StatusValidator(resellerapplication.Status(req.Status)); vErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_status", "unknown application status: "+req.Status, nil)
			return
		}
		// Idempotency guard, mirroring the equity flow exactly: a repeated PUT with the
		// status the application already holds is rejected rather than re-emitting the
		// domain event (which would re-run tenant creation/is_reseller flip on "approved").
		if string(current.Status) == req.Status {
			writeError(w, http.StatusConflict, "status_unchanged",
				"application is already in status "+req.Status,
				map[string]any{"application_id": id.String(), "status": req.Status})
			return
		}
		// State-machine enforcement (deliberately stricter than the equity flow, which
		// today accepts any status jump): pending → kyb_pending → kyb_approved →
		// agreement_pending → approved | rejected. See isValidResellerTransition.
		if !isValidResellerTransition(string(current.Status), req.Status) {
			writeError(w, http.StatusBadRequest, "invalid_transition",
				"cannot transition application from "+string(current.Status)+" to "+req.Status,
				map[string]any{"application_id": id.String(), "from": string(current.Status), "to": req.Status})
			return
		}
	}

	// The status write, the tenant resolution (create-new-vs-link-existing), and the
	// outbox event must commit together — mirroring legal_handler.go's equity
	// UpdateApplication exactly: a status change visible without its event (or a tenant
	// flipped to is_reseller without the status change) desynchronises downstream
	// consumers (a future treasury-api Reseller-provisioning consumer) permanently.
	tx, err := h.ent.Tx(ctx)
	if err != nil {
		h.logger.Error("failed to start transaction", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	upd := tx.ResellerApplication.UpdateOneID(id)
	if req.Status != "" {
		upd.SetStatus(resellerapplication.Status(req.Status))
	}
	if req.Notes != "" {
		upd.SetNotes(req.Notes)
	}
	if req.KybReference != "" {
		upd.SetKybReference(req.KybReference)
	}
	if req.KybResult != "" {
		upd.SetKybResult(req.KybResult)
	}
	if req.AgreementAcceptanceID != "" {
		if aid, err := uuid.Parse(req.AgreementAcceptanceID); err == nil {
			upd.SetAgreementAcceptanceID(aid)
		}
	}

	// On approval: resolve the reseller Tenant. If the applicant already had a tenant
	// (an existing tenant applying to also become a reseller), just flip is_reseller.
	// Otherwise (a brand-new business, no tenant yet) create one now — reusing the same
	// minimal Tenant.Create() shape autoProvisionExternalDeveloper already uses for
	// approval-time tenant creation (name/slug/status/contact fields), rather than the
	// full onboarding handlers (CreateTenant/CreateTenantPublic), which additionally
	// provision a trial subscription + HQ outlet that a reseller-only partner org does
	// not need at this stage.
	if req.Status == string(resellerapplication.StatusApproved) {
		if current.TenantID != nil {
			if _, err := tx.Tenant.UpdateOneID(*current.TenantID).SetIsReseller(true).Save(ctx); err != nil {
				_ = tx.Rollback()
				h.logger.Error("failed to flag existing tenant as reseller", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
				return
			}
		} else {
			slug := developerTenantSlug(current.BusinessName, current.ID)
			tCreate := tx.Tenant.Create().
				SetName(current.BusinessName).
				SetSlug(slug).
				SetStatus("active").
				SetIsReseller(true).
				SetContactEmail(current.ContactEmail)
			if current.ContactPhone != nil {
				tCreate.SetContactPhone(*current.ContactPhone)
			}
			if current.Country != nil {
				tCreate.SetCountry(*current.Country)
			}
			if current.TaxPin != nil {
				tCreate.SetTaxPin(*current.TaxPin)
			}
			newTenant, err := tCreate.Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				h.logger.Error("failed to create reseller tenant", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
				return
			}
			upd.SetTenantID(newTenant.ID)
		}
	}

	app, err := upd.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "application not found", nil)
			return
		}
		h.logger.Error("failed to update reseller application", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	// Emit a domain event on status change so downstream services can react — a future
	// treasury-api consumer (built separately) auto-creates its own Reseller record from
	// the "approved" event. Written through tx.Client() so a failed enqueue rolls the
	// status change (and any tenant resolution above) back instead of desyncing.
	if req.Status != "" {
		docVersion := ""
		var acceptedAt *time.Time
		if app.AgreementAcceptanceID != nil {
			if acc, accErr := tx.LegalAcceptance.Get(ctx, *app.AgreementAcceptanceID); accErr == nil {
				docVersion = acc.DocVersion
				at := acc.AcceptedAt
				acceptedAt = &at
			}
		}
		payload := resellerApplicationEventPayload(app, docVersion, acceptedAt)

		eventType := "status_updated"
		if app.Status == resellerapplication.StatusApproved {
			eventType = "approved"
		}

		outboxTenantID := uuid.Nil
		if app.TenantID != nil {
			outboxTenantID = *app.TenantID
		}

		if evErr := outbox.Write(ctx, tx.Client(), outboxTenantID,
			"auth.reseller_application", app.ID, eventType, "", payload); evErr != nil {
			_ = tx.Rollback()
			h.logger.Error("failed to enqueue reseller application event",
				zap.String("event_type", eventType), zap.Error(evErr))
			writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		h.logger.Error("failed to commit reseller application update", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update application", nil)
		return
	}

	writeJSON(w, http.StatusOK, toResellerApplicationResponse(app))
}

// ─── Pure decision logic (unit-tested without a DB) ──────────────────────────

// isValidResellerTransition reports whether moving a ResellerApplication from status
// "from" to status "to" is a legal step in the state machine:
//
//	pending → kyb_pending → kyb_approved → agreement_pending → approved | rejected
//
// Rejection is allowed from any non-terminal state (an admin can decline a bad
// application at any stage, not only right before approval). No transition is legal out
// of a terminal state (approved, rejected), no stage may be skipped, and no backward
// transition is legal. from==to is never a "transition" — callers reject that earlier as
// an idempotency no-op, not via this function.
func isValidResellerTransition(from, to string) bool {
	if from == "" || to == "" || from == to {
		return false
	}
	forward := map[string]string{
		string(resellerapplication.StatusPending):          string(resellerapplication.StatusKybPending),
		string(resellerapplication.StatusKybPending):       string(resellerapplication.StatusKybApproved),
		string(resellerapplication.StatusKybApproved):      string(resellerapplication.StatusAgreementPending),
		string(resellerapplication.StatusAgreementPending): string(resellerapplication.StatusApproved),
	}
	if forward[from] == to {
		return true
	}
	if to == string(resellerapplication.StatusRejected) {
		switch from {
		case string(resellerapplication.StatusPending),
			string(resellerapplication.StatusKybPending),
			string(resellerapplication.StatusKybApproved),
			string(resellerapplication.StatusAgreementPending):
			return true
		}
	}
	return false
}

// resellerApplicationEventPayload builds the auth.reseller_application.{approved,
// status_updated} outbox payload, mirroring the exact fields the equity flow forwards
// for auth.equity_holder_application.* (application_id, tenant_id, status, plus the
// signed-agreement version once present — see legal_handler.go's UpdateApplication),
// substituting reseller/business field names. Deliberately pure (reads only the already-
// loaded app + pre-resolved agreement fields, no ctx/DB access) so it is unit-testable
// without a database — the caller resolves docVersion/acceptedAt from the tx first.
func resellerApplicationEventPayload(app *ent.ResellerApplication, agreementDocVersion string, agreementAcceptedAt *time.Time) map[string]any {
	payload := map[string]any{
		"application_id": app.ID.String(),
		"status":         string(app.Status),
		"business_name":  app.BusinessName,
		"requested_tier": string(app.RequestedTier),
		"contact_email":  app.ContactEmail,
	}
	if app.TenantID != nil {
		payload["tenant_id"] = app.TenantID.String()
	}
	if app.BusinessRegistrationNo != nil {
		payload["business_registration_no"] = *app.BusinessRegistrationNo
	}
	if app.TaxPin != nil {
		payload["tax_pin"] = *app.TaxPin
	}
	if app.ContactPhone != nil {
		payload["contact_phone"] = *app.ContactPhone
	}
	if app.Country != nil {
		payload["country"] = *app.Country
	}
	if app.KybReference != "" {
		payload["kyb_reference"] = app.KybReference
	}
	if app.AgreementAcceptanceID != nil {
		payload["agreement_acceptance_id"] = app.AgreementAcceptanceID.String()
	}
	if agreementDocVersion != "" {
		payload["agreement_doc_version"] = agreementDocVersion
	}
	if agreementAcceptedAt != nil {
		payload["agreement_accepted_at"] = agreementAcceptedAt.Format(time.RFC3339)
	}
	return payload
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func toResellerApplicationResponse(a *ent.ResellerApplication) map[string]any {
	r := map[string]any{
		"id":             a.ID.String(),
		"business_name":  a.BusinessName,
		"contact_email":  a.ContactEmail,
		"requested_tier": string(a.RequestedTier),
		"status":         string(a.Status),
		"notes":          a.Notes,
		"created_at":     a.CreatedAt.Format(time.RFC3339),
		"updated_at":     a.UpdatedAt.Format(time.RFC3339),
	}
	if a.TenantID != nil {
		r["tenant_id"] = a.TenantID.String()
	}
	if a.BusinessRegistrationNo != nil {
		r["business_registration_no"] = *a.BusinessRegistrationNo
	}
	if a.TaxPin != nil {
		r["tax_pin"] = *a.TaxPin
	}
	if a.ContactPhone != nil {
		r["contact_phone"] = *a.ContactPhone
	}
	if a.Country != nil {
		r["country"] = *a.Country
	}
	if a.KybReference != "" {
		r["kyb_reference"] = a.KybReference
	}
	if a.KybResult != "" {
		r["kyb_result"] = a.KybResult
	}
	if a.AgreementAcceptanceID != nil {
		r["agreement_acceptance_id"] = a.AgreementAcceptanceID.String()
	}
	return r
}
