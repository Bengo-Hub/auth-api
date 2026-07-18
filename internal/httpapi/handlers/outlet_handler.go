package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/platform/outbox"
	"github.com/bengobox/auth-api/internal/services/usecase"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// OutletHandler manages outlet/branch CRUD and the outlet-selection SSO step.
type OutletHandler struct {
	ent    *ent.Client
	tokens *token.Service
	logger *zap.Logger
}

func NewOutletHandler(entClient *ent.Client, tokens *token.Service, logger *zap.Logger) *OutletHandler {
	return &OutletHandler{ent: entClient, tokens: tokens, logger: logger}
}

// ─── Request / Response types ────────────────────────────────────────────────

type outletRequest struct {
	Code             string         `json:"code"`
	Name             string         `json:"name"`
	UseCase          string         `json:"use_case"`
	Address          string         `json:"address,omitempty"`
	Timezone         string         `json:"timezone,omitempty"`
	IsHQ             bool           `json:"is_hq,omitempty"`
	Status           string         `json:"status,omitempty"`
	PinLoginMessage  string         `json:"pin_login_message,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

type outletResponse struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"tenant_id"`
	Code               string         `json:"code"`
	Name               string         `json:"name"`
	UseCase            string         `json:"use_case"`
	ApplicableServices []string       `json:"applicable_services"`
	Address            *string        `json:"address,omitempty"`
	Timezone           *string        `json:"timezone,omitempty"`
	IsHQ               bool           `json:"is_hq"`
	Status             string         `json:"status"`
	PinLoginMessage    *string        `json:"pin_login_message,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

type selectOutletRequest struct {
	SSOExchangeToken string `json:"sso_exchange_token"`
	OutletID         string `json:"outlet_id"`
}

func outletToResponse(o *ent.Outlet) outletResponse {
	return outletResponse{
		ID:                 o.ID.String(),
		TenantID:           o.TenantID.String(),
		Code:               o.Code,
		Name:               o.Name,
		UseCase:            o.UseCase,
		ApplicableServices: usecase.ApplicableServices(o.UseCase),
		Address:            o.Address,
		Timezone:           o.Timezone,
		IsHQ:               o.IsHq,
		Status:             o.Status,
		PinLoginMessage:    o.PinLoginMessage,
		Metadata:           o.Metadata,
		CreatedAt:          o.CreatedAt,
		UpdatedAt:          o.UpdatedAt,
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (h *OutletHandler) resolveTenantFromSlug(ctx context.Context, slug string) (*ent.Tenant, error) {
	return h.ent.Tenant.Query().Where(tenant.Slug(slug)).Only(ctx)
}

func (h *OutletHandler) requireTenantAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}
	if claims.IsPlatformOwner {
		return true
	}
	// Accept every tenant-admin-equivalent role. This MUST stay in sync with the
	// auth-ui TENANT_ADMIN_ROLES set (useAuth.ts) — otherwise a user the UI shows the
	// branch-management form to (e.g. role "owner"/"tenant_admin") gets a 403 here.
	for _, role := range claims.Roles {
		switch role {
		case "superuser", "admin", "owner", "super_admin", "tenant_admin":
			return true
		}
	}
	return false
}

// withOutletContacts merges the location/contact payload keys into an outlet event payload so
// downstream mirrors (pos receipts, inventory) stay in sync: the physical address/location and
// the freeform metadata — notably metadata.contact_phones, a list of {label, value} pairs
// (e.g. {label:"MTN", value:"+256782323113"}) printed on receipts as the "Mobile:" line.
func withOutletContacts(data map[string]any, o *ent.Outlet) map[string]any {
	if o.Address != nil && *o.Address != "" {
		data["address"] = *o.Address
	}
	if len(o.Metadata) > 0 {
		data["metadata"] = o.Metadata
	}
	return data
}

func (h *OutletHandler) publishOutletEvent(ctx context.Context, tenantID, outletID uuid.UUID, eventType string, data map[string]any) {
	if err := outbox.Write(ctx, h.ent, tenantID, "auth.outlet", outletID, eventType, "", data); err != nil {
		h.logger.Warn("failed to write outlet outbox event", zap.Error(err))
	}
}

// ─── CRUD handlers ────────────────────────────────────────────────────────────

// ensureHQOutlet get-or-creates a tenant's HQ "MAIN" outlet so a tenant is never
// left with zero outlets (which would block the SSO "Select View" / outlet picker
// with "No outlets found"). Auth-api OWNS outlets, so creating it here guarantees a
// single stable UUID that every downstream service (inventory, pos, library,
// treasury) mirrors via the auth.outlet.created event — UUID uniformity is automatic
// because the UUID is minted once, by the owner, and propagated, never re-minted.
//
// Idempotent: the unique (tenant_id, code) index makes a concurrent second create
// fail harmlessly, and we re-query on a lost race. Mirrors the get-or-create-HQ
// pattern library-service uses in EnsureDefaultBranch.
//
// Returns the full outlet list for the tenant (existing or freshly seeded).
func (h *OutletHandler) ensureHQOutlet(ctx context.Context, t *ent.Tenant) ([]*ent.Outlet, error) {
	outlets, err := h.ent.Outlet.Query().
		Where(outlet.TenantID(t.ID)).
		Order(ent.Asc(outlet.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(outlets) > 0 {
		return outlets, nil
	}

	// No outlets for this tenant — provision the default HQ "MAIN" outlet on the fly.
	// Reuse the tenant's primary use_case so downstream route-gating is correct.
	hqUseCase := "hospitality"
	if t.UseCase != nil && *t.UseCase != "" && usecase.IsValidUseCase(*t.UseCase) {
		hqUseCase = *t.UseCase
	}
	hqName := "Main / HQ"
	if t.Name != "" {
		hqName = t.Name + " HQ"
	}

	created, cerr := h.ent.Outlet.Create().
		SetTenantID(t.ID).
		SetCode("MAIN").
		SetName(hqName).
		SetUseCase(hqUseCase).
		SetIsHq(true).
		SetStatus("active").
		Save(ctx)
	if cerr != nil {
		// Lost a race (another request created MAIN) — re-query and return whatever exists.
		outlets, qerr := h.ent.Outlet.Query().
			Where(outlet.TenantID(t.ID)).
			Order(ent.Asc(outlet.FieldCreatedAt)).
			All(ctx)
		if qerr == nil && len(outlets) > 0 {
			return outlets, nil
		}
		return nil, cerr
	}

	// Emit auth.outlet.created so inventory/pos/library/treasury mirror the SAME UUID.
	h.publishOutletEvent(ctx, t.ID, created.ID, "created", withOutletContacts(map[string]any{
		"outlet_id":           created.ID.String(),
		"tenant_id":           t.ID.String(),
		"tenant_slug":         t.Slug,
		"code":                created.Code,
		"name":                created.Name,
		"use_case":            created.UseCase,
		"is_hq":               created.IsHq,
		"status":              created.Status,
		"applicable_services": usecase.ApplicableServices(created.UseCase),
	}, created))
	h.logger.Info("auto-provisioned default HQ outlet for tenant with none",
		zap.String("tenant_slug", t.Slug),
		zap.String("outlet_id", created.ID.String()))

	return []*ent.Outlet{created}, nil
}

// ListOutlets GET /api/v1/tenants/{slug}/outlets
func (h *OutletHandler) ListOutlets(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	t, err := h.resolveTenantFromSlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}

	// Never let the SSO outlet picker hit "No outlets found": get-or-create the HQ
	// MAIN outlet when the tenant has none (heals tenants provisioned before HQ
	// auto-creation existed, or whose HQ event was never delivered).
	outlets, err := h.ensureHQOutlet(r.Context(), t)
	if err != nil {
		h.logger.Error("list outlets", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]outletResponse, len(outlets))
	for i, o := range outlets {
		resp[i] = outletToResponse(o)
	}
	writeJSON(w, http.StatusOK, resp)
}

// CreateOutlet POST /api/v1/tenants/{slug}/outlets
func (h *OutletHandler) CreateOutlet(w http.ResponseWriter, r *http.Request) {
	if !h.requireTenantAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	slug := chi.URLParam(r, "slug")
	t, err := h.resolveTenantFromSlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}

	var req outletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.Code == "" || req.Name == "" {
		http.Error(w, "code and name are required", http.StatusBadRequest)
		return
	}

	// If is_hq is set, clear it from existing outlets first (only one HQ allowed).
	if req.IsHQ {
		h.ent.Outlet.Update().
			Where(outlet.TenantID(t.ID), outlet.IsHq(true)).
			SetIsHq(false).
			Exec(r.Context()) //nolint:errcheck
	}

	useCase := req.UseCase
	if useCase == "" {
		useCase = "hospitality"
	}
	if !usecase.IsValidUseCase(useCase) {
		http.Error(w, "invalid use_case: must be one of "+strings.Join(usecase.KnownUseCases, ", "), http.StatusUnprocessableEntity)
		return
	}
	status := req.Status
	if status == "" {
		status = "active"
	}
	tz := req.Timezone
	if tz == "" {
		tz = "Africa/Nairobi"
	}

	create := h.ent.Outlet.Create().
		SetTenantID(t.ID).
		SetCode(req.Code).
		SetName(req.Name).
		SetUseCase(useCase).
		SetStatus(status).
		SetTimezone(tz).
		SetIsHq(req.IsHQ)

	if req.Address != "" {
		create = create.SetAddress(req.Address)
	}
	if req.PinLoginMessage != "" {
		create = create.SetPinLoginMessage(req.PinLoginMessage)
	}
	if req.Metadata != nil {
		create = create.SetMetadata(req.Metadata)
	}

	o, err := create.Save(r.Context())
	if err != nil {
		if ent.IsConstraintError(err) {
			http.Error(w, "outlet code already exists for this tenant", http.StatusConflict)
			return
		}
		h.logger.Error("create outlet", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.publishOutletEvent(r.Context(), t.ID, o.ID, "created", withOutletContacts(map[string]any{
		"outlet_id":           o.ID.String(),
		"tenant_id":           t.ID.String(),
		"tenant_slug":         t.Slug,
		"code":                o.Code,
		"name":                o.Name,
		"use_case":            o.UseCase,
		"is_hq":               o.IsHq,
		"applicable_services": usecase.ApplicableServices(o.UseCase),
	}, o))

	writeJSON(w, http.StatusCreated, outletToResponse(o))
}

// UpdateOutlet PUT /api/v1/tenants/{slug}/outlets/{outlet_id}
func (h *OutletHandler) UpdateOutlet(w http.ResponseWriter, r *http.Request) {
	if !h.requireTenantAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	slug := chi.URLParam(r, "slug")
	outletIDStr := chi.URLParam(r, "outlet_id")
	outletID, err := uuid.Parse(outletIDStr)
	if err != nil {
		http.Error(w, "invalid outlet id", http.StatusBadRequest)
		return
	}

	t, err := h.resolveTenantFromSlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}

	var req outletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	// Verify the outlet belongs to this tenant.
	existing, err := h.ent.Outlet.Get(r.Context(), outletID)
	if err != nil || existing.TenantID != t.ID {
		http.Error(w, "outlet not found", http.StatusNotFound)
		return
	}

	// If promoting to HQ, demote any existing HQ.
	if req.IsHQ && !existing.IsHq {
		h.ent.Outlet.Update().
			Where(outlet.TenantID(t.ID), outlet.IsHq(true)).
			SetIsHq(false).
			Exec(r.Context()) //nolint:errcheck
	}

	if req.UseCase != "" && !usecase.IsValidUseCase(req.UseCase) {
		http.Error(w, "invalid use_case: must be one of "+strings.Join(usecase.KnownUseCases, ", "), http.StatusUnprocessableEntity)
		return
	}

	update := h.ent.Outlet.UpdateOneID(outletID)
	if req.Name != "" {
		update = update.SetName(req.Name)
	}
	if req.UseCase != "" {
		update = update.SetUseCase(req.UseCase)
	}
	if req.Status != "" {
		update = update.SetStatus(req.Status)
	}
	if req.Address != "" {
		update = update.SetAddress(req.Address)
	}
	if req.Timezone != "" {
		update = update.SetTimezone(req.Timezone)
	}
	if req.PinLoginMessage != "" {
		update = update.SetPinLoginMessage(req.PinLoginMessage)
	}
	if req.Metadata != nil {
		update = update.SetMetadata(req.Metadata)
	}
	update = update.SetIsHq(req.IsHQ)

	o, err := update.Save(r.Context())
	if err != nil {
		h.logger.Error("update outlet", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.publishOutletEvent(r.Context(), t.ID, o.ID, "updated", withOutletContacts(map[string]any{
		"outlet_id":           o.ID.String(),
		"tenant_id":           t.ID.String(),
		"tenant_slug":         t.Slug,
		"code":                o.Code,
		"name":                o.Name,
		"use_case":            o.UseCase,
		"is_hq":               o.IsHq,
		"status":              o.Status,
		"applicable_services": usecase.ApplicableServices(o.UseCase),
	}, o))

	writeJSON(w, http.StatusOK, outletToResponse(o))
}

// ArchiveOutlet DELETE /api/v1/tenants/{slug}/outlets/{outlet_id}
func (h *OutletHandler) ArchiveOutlet(w http.ResponseWriter, r *http.Request) {
	if !h.requireTenantAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	slug := chi.URLParam(r, "slug")
	outletIDStr := chi.URLParam(r, "outlet_id")
	outletID, err := uuid.Parse(outletIDStr)
	if err != nil {
		http.Error(w, "invalid outlet id", http.StatusBadRequest)
		return
	}

	t, err := h.resolveTenantFromSlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}

	existing, err := h.ent.Outlet.Get(r.Context(), outletID)
	if err != nil || existing.TenantID != t.ID {
		http.Error(w, "outlet not found", http.StatusNotFound)
		return
	}

	if _, err := h.ent.Outlet.UpdateOneID(outletID).SetStatus("archived").Save(r.Context()); err != nil {
		h.logger.Error("archive outlet", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.publishOutletEvent(r.Context(), t.ID, outletID, "archived", map[string]any{
		"outlet_id": outletID.String(),
		"tenant_id": t.ID.String(),
	})

	w.WriteHeader(http.StatusNoContent)
}

// SelectOutlet POST /api/v1/auth/select-outlet
//
// After SSO login, a multi-outlet user is issued a short-lived sso_exchange_token
// (plain JWT with no outlet claim). This endpoint receives that token + the chosen
// outletID and re-issues a full access token with outlet claims embedded.
func (h *OutletHandler) SelectOutlet(w http.ResponseWriter, r *http.Request) {
	var req selectOutletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.SSOExchangeToken == "" || req.OutletID == "" {
		http.Error(w, "sso_exchange_token and outlet_id are required", http.StatusBadRequest)
		return
	}

	// Validate the exchange token.
	claims, err := h.tokens.Parse(req.SSOExchangeToken)
	if err != nil {
		http.Error(w, "invalid or expired exchange token", http.StatusUnauthorized)
		return
	}

	outletID, err := uuid.Parse(req.OutletID)
	if err != nil {
		http.Error(w, "invalid outlet_id", http.StatusBadRequest)
		return
	}

	// Resolve the outlet and verify it belongs to the user's tenant.
	tenantID, err := uuid.Parse(claims.TenantID)
	if err != nil {
		http.Error(w, "token missing tenant_id", http.StatusUnauthorized)
		return
	}

	o, err := h.ent.Outlet.Get(r.Context(), outletID)
	if err != nil || o.TenantID != tenantID {
		http.Error(w, "outlet not found or access denied", http.StatusForbidden)
		return
	}
	if o.Status != "active" {
		http.Error(w, "outlet is not active", http.StatusForbidden)
		return
	}

	// Re-mint the access token with outlet claims.
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		http.Error(w, "invalid token subject", http.StatusUnauthorized)
		return
	}
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		sessionID = uuid.New()
	}

	newToken, _, err := h.tokens.MintAccessToken(token.AccessTokenInput{
		UserID:          userID,
		TenantID:        &tenantID,
		TenantSlug:      claims.TenantSlug,
		SessionID:       sessionID,
		Email:           claims.Email,
		Scopes:          claims.Scope,
		Roles:           claims.Roles,
		Permissions:     claims.Permissions,
		IsPlatformOwner: claims.IsPlatformOwner,
		OutletID:        o.ID.String(),
		OutletCode:      o.Code,
		OutletUseCase:   o.UseCase,
		IsHQUser:        o.IsHq,
		SubscriptionPlan:     claims.SubscriptionPlan,
		SubscriptionStatus:   claims.SubscriptionStatus,
		SubscriptionFeatures: claims.SubscriptionFeatures,
		SubscriptionLimits:   claims.SubscriptionLimits,
	})
	if err != nil {
		h.logger.Error("mint outlet token", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": newToken,
		"outlet": map[string]any{
			"id":       o.ID.String(),
			"code":     o.Code,
			"name":     o.Name,
			"use_case": o.UseCase,
			"is_hq":    o.IsHq,
		},
	})
}

// GetCurrentOutlet GET /api/v1/auth/outlets/current
// Returns the outlet embedded in the authenticated user's JWT.
func (h *OutletHandler) GetCurrentOutlet(w http.ResponseWriter, r *http.Request) {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if claims.OutletID == "" {
		writeJSON(w, http.StatusOK, map[string]any{"outlet": nil})
		return
	}

	outletID, err := uuid.Parse(claims.OutletID)
	if err != nil {
		http.Error(w, "invalid outlet claim", http.StatusBadRequest)
		return
	}

	o, err := h.ent.Outlet.Get(r.Context(), outletID)
	if err != nil {
		http.Error(w, "outlet not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"outlet": outletToResponse(o)})
}

// RepublishOutletEvents POST /internal/outlets/republish?slug={tenantSlug}
// Re-publishes auth.outlet.updated events for all active outlets of the given tenant.
// Secured by INTERNAL_SERVICE_KEY (X-API-Key header). Used to re-sync downstream
// services (ordering-backend, pos-api) when NATS events have expired from the stream.
func (h *OutletHandler) RepublishOutletEvents(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("slug")
	if slug == "" {
		http.Error(w, "slug query param required", http.StatusBadRequest)
		return
	}

	t, err := h.resolveTenantFromSlug(r.Context(), slug)
	if err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}

	outlets, err := h.ent.Outlet.Query().
		Where(outlet.TenantID(t.ID)).
		All(r.Context())
	if err != nil {
		h.logger.Error("republish: query outlets", zap.Error(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	count := 0
	for _, o := range outlets {
		eventType := "updated"
		if o.Status == "archived" {
			eventType = "archived"
		}
		h.publishOutletEvent(r.Context(), t.ID, o.ID, eventType, withOutletContacts(map[string]any{
			"outlet_id":           o.ID.String(),
			"tenant_id":           t.ID.String(),
			"tenant_slug":         t.Slug,
			"code":                o.Code,
			"name":                o.Name,
			"use_case":            o.UseCase,
			"is_hq":               o.IsHq,
			"status":              o.Status,
			"applicable_services": usecase.ApplicableServices(o.UseCase),
		}, o))
		count++
	}

	h.logger.Info("outlet events republished", zap.String("tenant", slug), zap.Int("count", count))
	writeJSON(w, http.StatusOK, map[string]any{
		"republished": count,
		"tenant":      slug,
	})
}

