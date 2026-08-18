package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/Bengo-Hub/pagination"
	subscriptionclient "github.com/bengobox/auth-api/internal/clients/subscription"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	entoutlet "github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/password"
	"github.com/bengobox/auth-api/internal/pkg/imageutil"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/services/entitlements"
	"github.com/bengobox/auth-api/internal/services/integrations"
	"github.com/bengobox/auth-api/internal/services/usage"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// AdminHandler provides basic tenant/client admin APIs.
type AdminHandler struct {
	ent          *ent.Client
	logger       *zap.Logger
	entSvc       *entitlements.Service
	useSvc       *usage.Service
	tokens       *token.Service
	integrations *integrations.Service
	subClient    *subscriptionclient.Client
	hasher       *password.Hasher
	authUIURL    string
}

func NewAdminHandler(entClient *ent.Client, tokens *token.Service, integrationSvc *integrations.Service, subClient *subscriptionclient.Client, hasher *password.Hasher, authUIURL string, logger *zap.Logger) *AdminHandler {
	return &AdminHandler{
		ent:          entClient,
		logger:       logger,
		entSvc:       entitlements.New(entClient),
		useSvc:       usage.New(entClient),
		tokens:       tokens,
		integrations: integrationSvc,
		subClient:    subClient,
		hasher:       hasher,
		authUIURL:    authUIURL,
	}
}

// requireAdmin gates PLATFORM-WIDE actions (tenant CRUD, OAuth client CRUD,
// key rotation, entitlements, integration configs, usage) that have no
// per-tenant scoping of their own. It MUST NOT accept a bare "admin"/
// "superuser" role string: those role names are reused by every ordinary
// tenant (e.g. the admin of Urban Loft Cafe), and TenantMembership roles are
// tenant-scoped, not global — accepting them here previously let any single
// tenant's admin manage every tenant on the platform. Use requireTenantAdmin
// instead for actions scoped to the caller's own tenant.
func (h *AdminHandler) requireAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}

	// Platform owners (admin-tier role within the "codevertex" tenant) bypass all RBAC.
	if claims.IsPlatformOwner {
		return true
	}

	// Explicit admin scopes (for service-to-service tokens).
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// requireTenantAdmin authorizes admin actions that target a specific tenant.
// Platform owners and S2S admin-scoped tokens bypass the tenant check. A tenant
// admin/superuser is only allowed when their token's tenant matches the target
// tenant — this prevents cross-tenant writes (a tenant A admin acting on tenant B).
func (h *AdminHandler) requireTenantAdmin(r *http.Request, tenantID uuid.UUID) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}

	// Platform owners (primary tenant = "codevertex") bypass all RBAC.
	if claims.IsPlatformOwner {
		return true
	}

	// Service-to-service tokens with explicit admin scope (no tenant binding).
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}

	// Tenant admins may only act on their own tenant.
	if claims.TenantID == "" || claims.TenantID != tenantID.String() {
		return false
	}
	for _, role := range claims.Roles {
		if role == "superuser" || role == "admin" {
			return true
		}
	}
	return false
}

// publishEvent writes a domain event to the outbox for async NATS publishing.
func (h *AdminHandler) publishEvent(ctx context.Context, tenantID uuid.UUID, aggregateType string, aggregateID uuid.UUID, eventType string, data map[string]any) {
	writeOutboxEvent(ctx, h.ent, h.logger, tenantID, aggregateType, aggregateID, eventType, data)
}

func (h *AdminHandler) publishTenantEvent(ctx context.Context, t *ent.Tenant, createdBy string) {
	h.publishTenantLifecycleEvent(ctx, t, "created", createdBy)
}

// publishTenantLifecycleEvent emits auth.tenant.{created|updated} carrying the
// business identity + tax/KRA details so downstream services (treasury-api) can
// sync the tenant's invoice issuer block and payment-details config.
func (h *AdminHandler) publishTenantLifecycleEvent(ctx context.Context, t *ent.Tenant, eventType, actor string) {
	useCase := ""
	if t.UseCase != nil {
		useCase = *t.UseCase
	}
	h.publishEvent(ctx, t.ID, "auth.tenant", t.ID, eventType, map[string]any{
		"tenant_id":         t.ID.String(),
		"name":              t.Name,
		"slug":              t.Slug,
		"use_case":          useCase,
		"created_by":        actor,
		"is_demo":           t.IsDemo,
		"tax_pin":           t.TaxPin,
		"vat_registered":    t.VatRegistered,
		"vat_registered_on": t.VatRegisteredOn,
		"country":           t.Country,
		"timezone":          t.Timezone,
	})
}

// Tenants — accepts every field the tenant entity can carry so the frontend
// can POST/PUT a full tenant object without triggering DisallowUnknownFields.
// Fields the update handler ignores (status, subscription_*) are read-only.
type tenantRequest struct {
	ID                    string                 `json:"id,omitempty"`
	Name                  string                 `json:"name"`
	Slug                  string                 `json:"slug"`
	Status                string                 `json:"status,omitempty"`  // read-only; ignored on update
	IsDemo                *bool                  `json:"is_demo,omitempty"` // platform-admin only; excludes from platform revenue
	UseCase               string                 `json:"use_case,omitempty"`
	UseCases              []string               `json:"use_cases,omitempty"`
	ContactEmail          string                 `json:"contact_email,omitempty"`
	ContactPhone          string                 `json:"contact_phone,omitempty"`
	SubscriptionPlan      string                 `json:"subscription_plan,omitempty"`
	SubscriptionStatus    string                 `json:"subscription_status,omitempty"`
	SubscriptionExpiresAt *string                `json:"subscription_expires_at,omitempty"`
	HQBranchName          string                 `json:"hq_branch_name,omitempty"`
	LogoURL               string                 `json:"logo_url,omitempty"`
	Website               string                 `json:"website,omitempty"`
	BrandColors           map[string]any         `json:"brand_colors,omitempty"`
	OrgSize               string                 `json:"org_size,omitempty"`
	Country               string                 `json:"country,omitempty"`
	Timezone              string                 `json:"timezone,omitempty"`
	TierLimits            map[string]any         `json:"tier_limits,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
	// Tax / KRA compliance (Zoho Books-style). Pointers so update can tell
	// "field omitted" (nil) from "explicitly cleared" (empty/false).
	TaxPin          *string `json:"tax_pin,omitempty"`           // KRA PIN
	VatRegistered   *bool   `json:"vat_registered,omitempty"`    // registered for VAT?
	VatRegisteredOn *string `json:"vat_registered_on,omitempty"` // ISO date (YYYY-MM-DD)
	CreatedAt       *string `json:"created_at,omitempty"`
	UpdatedAt       *string `json:"updated_at,omitempty"`
}

// parseTenantTaxDate parses an optional ISO date/timestamp string into *time.Time.
func parseTenantTaxDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return &t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

func (h *AdminHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req tenantRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" || req.Slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	create := h.ent.Tenant.Create().
		SetName(req.Name).
		SetSlug(req.Slug).
		SetUseCase(req.UseCase).
		SetStatus("active")

	// Tax / KRA compliance captured at onboarding.
	if req.TaxPin != nil && strings.TrimSpace(*req.TaxPin) != "" {
		create.SetTaxPin(strings.TrimSpace(*req.TaxPin))
	}
	if req.VatRegistered != nil {
		create.SetVatRegistered(*req.VatRegistered)
	}
	if req.VatRegisteredOn != nil {
		if d := parseTenantTaxDate(*req.VatRegisteredOn); d != nil {
			create.SetVatRegisteredOn(*d)
		}
	}
	if req.IsDemo != nil {
		create.SetIsDemo(*req.IsDemo)
	}
	// IANA timezone (day/shift boundaries downstream). Falls back to the schema
	// default (Africa/Nairobi) when the request omits it.
	if tz := strings.TrimSpace(req.Timezone); tz != "" {
		create.SetTimezone(tz)
	}
	if c := strings.TrimSpace(req.Country); c != "" {
		create.SetCountry(c)
	}

	// If tenant ID is provided, use it (for cross-service tenant sync)
	if req.ID != "" {
		tenantID, err := uuid.Parse(req.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant ID format", nil)
			return
		}
		create.SetID(tenantID)
	}

	// Set optional fields (contact info stored in metadata since schema doesn't have those fields)
	metadata := make(map[string]interface{})
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	if req.ContactEmail != "" {
		metadata["contact_email"] = req.ContactEmail
	}
	if req.ContactPhone != "" {
		metadata["contact_phone"] = req.ContactPhone
	}
	if len(metadata) > 0 {
		create.SetMetadata(metadata)
	}

	t, err := create.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "conflict", "could not create tenant", nil)
		return
	}

	// Provision live trial subscription from subscription-api.
	plan := req.SubscriptionPlan
	if plan == "" && h.subClient != nil {
		// Pull default STARTER plan from subscription-api if none specified
		p, err := h.subClient.GetPlanByCode(r.Context(), "STARTER")
		if err != nil {
			h.logger.Warn("failed to fetch default STARTER plan", zap.Error(err))
		} else if p != nil {
			plan = p.PlanCode
		}
	}

	if plan != "" && h.subClient != nil {
		sub, err := h.subClient.CreateTrialSubscription(r.Context(), t.ID, plan, t.Slug, t.Name)
		if err != nil {
			h.logger.Warn("failed to provision trial subscription", zap.String("tenant_id", t.ID.String()), zap.Error(err))
		} else {
			// Update tenant with live subscription data
			t, _ = h.ent.Tenant.UpdateOne(t).
				SetSubscriptionID(sub.ID.String()).
				SetSubscriptionPlan(sub.PlanCode).
				SetSubscriptionStatus(sub.Status).
				SetNillableSubscriptionExpiresAt(sub.TrialEndsAt).
				Save(r.Context())
		}
	}

	// Publish tenant.created event
	claims, _ := authmiddleware.ClaimsFromContext(r.Context())
	createdBy := ""
	if claims != nil {
		createdBy = claims.Subject
	}
	useCase := ""
	if t.UseCase != nil {
		useCase = *t.UseCase
	}
	h.publishTenantEvent(r.Context(), t, createdBy)

	// Initialize default HQ outlet — persisted to DB + event published.
	// This is the source-of-truth record that downstream services (pos-api, inventory-api)
	// sync from via auth.outlet.created NATS events.
	hqName := "Main / HQ"
	if req.HQBranchName != "" {
		hqName = req.HQBranchName
	}
	hqOutlet, err := h.ent.Outlet.Create().
		SetTenantID(t.ID).
		SetCode("MAIN").
		SetName(hqName).
		SetUseCase(useCase).
		SetIsHq(true).
		SetStatus("active").
		Save(r.Context())
	if err != nil {
		h.logger.Warn("failed to create default HQ outlet", zap.String("tenant_id", t.ID.String()), zap.Error(err))
	} else {
		h.publishEvent(r.Context(), t.ID, "auth.outlet", hqOutlet.ID, "created", map[string]any{
			"outlet_id": hqOutlet.ID.String(),
			"tenant_id": t.ID.String(),
			"code":      hqOutlet.Code,
			"name":      hqOutlet.Name,
			"use_case":  hqOutlet.UseCase,
			"is_hq":     hqOutlet.IsHq,
		})
	}

	// Auto-register redirect URIs for the new tenant slug on all OAuth clients.
	if err := auth.AppendTenantRedirectURIs(r.Context(), h.ent, t.Slug); err != nil {
		h.logger.Warn("failed to append tenant redirect URIs",
			zap.String("tenant_slug", t.Slug),
			zap.Error(err),
		)
	}

	writeJSON(w, http.StatusCreated, t)
}

// CreateTenantPublic creates a tenant for cross-service tenant sync/auto-discovery.
// Despite the name, this is NOT reachable without authentication — router.go gates
// it behind the internal-service-key middleware (same as /api/v1/s2s/*), since it
// lets the caller choose the tenant's own ID and creates it active outright.
func (h *AdminHandler) CreateTenantPublic(w http.ResponseWriter, r *http.Request) {
	var req tenantRequest
	if err := decodeJSON(r, &req); err != nil || req.Slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload: slug is required", nil)
		return
	}

	// Name is required, use slug as fallback
	if req.Name == "" {
		req.Name = req.Slug
	}

	create := h.ent.Tenant.Create().
		SetName(req.Name).
		SetSlug(req.Slug).
		SetUseCase(req.UseCase).
		SetStatus("active")

	// Tax / KRA compliance captured at onboarding.
	if req.TaxPin != nil && strings.TrimSpace(*req.TaxPin) != "" {
		create.SetTaxPin(strings.TrimSpace(*req.TaxPin))
	}
	if req.VatRegistered != nil {
		create.SetVatRegistered(*req.VatRegistered)
	}
	if req.VatRegisteredOn != nil {
		if d := parseTenantTaxDate(*req.VatRegisteredOn); d != nil {
			create.SetVatRegisteredOn(*d)
		}
	}
	// IANA timezone (day/shift boundaries downstream); schema default Africa/Nairobi when omitted.
	if tz := strings.TrimSpace(req.Timezone); tz != "" {
		create.SetTimezone(tz)
	}
	if c := strings.TrimSpace(req.Country); c != "" {
		create.SetCountry(c)
	}

	// If tenant ID is provided, use it (for cross-service tenant sync with matching UUIDs)
	if req.ID != "" {
		tenantID, err := uuid.Parse(req.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant ID format", nil)
			return
		}
		create.SetID(tenantID)
	}

	// Set optional fields (contact info stored in metadata since schema doesn't have those fields)
	metadata := make(map[string]interface{})
	if req.Metadata != nil {
		metadata = req.Metadata
	}
	if req.ContactEmail != "" {
		metadata["contact_email"] = req.ContactEmail
	}
	if req.ContactPhone != "" {
		metadata["contact_phone"] = req.ContactPhone
	}
	if len(metadata) > 0 {
		create.SetMetadata(metadata)
	}

	t, err := create.Save(r.Context())
	if err != nil {
		// Check if tenant already exists (idempotent)
		existing, err := h.ent.Tenant.Query().
			Where(tenant.SlugEQ(req.Slug)).
			Only(r.Context())
		if err == nil && existing != nil {
			writeJSON(w, http.StatusOK, existing)
			return
		}
		writeError(w, http.StatusBadRequest, "conflict", "could not create tenant", nil)
		return
	}

	// Provision live trial subscription from subscription-api.
	plan := req.SubscriptionPlan
	if plan == "" && h.subClient != nil {
		// Pull default STARTER plan from subscription-api if none specified
		p, err := h.subClient.GetPlanByCode(r.Context(), "STARTER")
		if err != nil {
			h.logger.Warn("failed to fetch default STARTER plan", zap.Error(err))
		} else if p != nil {
			plan = p.PlanCode
		}
	}

	if plan != "" && h.subClient != nil {
		sub, err := h.subClient.CreateTrialSubscription(r.Context(), t.ID, plan, t.Slug, t.Name)
		if err != nil {
			h.logger.Warn("failed to provision trial subscription", zap.String("tenant_id", t.ID.String()), zap.Error(err))
		} else {
			t, _ = h.ent.Tenant.UpdateOne(t).
				SetSubscriptionID(sub.ID.String()).
				SetSubscriptionPlan(sub.PlanCode).
				SetSubscriptionStatus(sub.Status).
				SetNillableSubscriptionExpiresAt(sub.TrialEndsAt).
				Save(r.Context())
		}
	}

	// Publish tenant.created event
	useCase := ""
	if t.UseCase != nil {
		useCase = *t.UseCase
	}
	h.publishTenantEvent(r.Context(), t, "self-service")

	// Initialize default HQ outlet in DB + publish auth.outlet.created.
	hqName := "Main / HQ"
	if req.HQBranchName != "" {
		hqName = req.HQBranchName
	}
	hqOutletPub, pubErr := h.ent.Outlet.Create().
		SetTenantID(t.ID).
		SetCode("MAIN").
		SetName(hqName).
		SetUseCase(useCase).
		SetIsHq(true).
		SetStatus("active").
		Save(r.Context())
	if pubErr != nil {
		h.logger.Warn("failed to create default HQ outlet (public)", zap.String("tenant_id", t.ID.String()), zap.Error(pubErr))
	} else {
		h.publishEvent(r.Context(), t.ID, "auth.outlet", hqOutletPub.ID, "created", map[string]any{
			"outlet_id": hqOutletPub.ID.String(),
			"tenant_id": t.ID.String(),
			"code":      hqOutletPub.Code,
			"name":      hqOutletPub.Name,
			"use_case":  hqOutletPub.UseCase,
			"is_hq":     hqOutletPub.IsHq,
		})
	}

	writeJSON(w, http.StatusCreated, t)
}

// PublicTenantResponse is the response for GET /api/v1/tenants/by-slug/{slug} (public, no auth).
// Used by frontends for tenant auto-discovery and branding (name, slug, metadata.primary_color, etc.).
type PublicTenantResponse struct {
	ID                    string         `json:"id"`
	Name                  string         `json:"name"`
	Slug                  string         `json:"slug"`
	Status                string         `json:"status"`
	IsDemo                bool           `json:"is_demo"`
	ContactEmail          *string        `json:"contact_email,omitempty"`
	ContactPhone          *string        `json:"contact_phone,omitempty"`
	LogoURL               *string        `json:"logo_url,omitempty"`
	Website               *string        `json:"website,omitempty"`
	Country               *string        `json:"country,omitempty"`
	Timezone              *string        `json:"timezone,omitempty"`
	BrandColors           map[string]any `json:"brand_colors,omitempty"`
	OrgSize               *string        `json:"org_size,omitempty"`
	UseCase               *string        `json:"use_case,omitempty"`
	UseCases              []string       `json:"use_cases,omitempty"`
	SubscriptionPlan      *string        `json:"subscription_plan,omitempty"`
	SubscriptionStatus    *string        `json:"subscription_status,omitempty"`
	SubscriptionExpiresAt *time.Time     `json:"subscription_expires_at,omitempty"`
	TierLimits            map[string]any `json:"tier_limits,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
	// Tax / KRA compliance — consumed by treasury-ui to pre-fill payment-details.
	TaxPin          *string    `json:"tax_pin,omitempty"`
	VatRegistered   bool       `json:"vat_registered"`
	VatRegisteredOn *time.Time `json:"vat_registered_on,omitempty"`
}

// GetTenantBySlugPublic retrieves a tenant by slug via public endpoint (for tenant auto-discovery and branding).
// No authentication required. Returns id, name, slug, status, and metadata (e.g. logo_url, primary_color for brand).
func (h *AdminHandler) GetTenantBySlugPublic(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "slug is required", nil)
		return
	}

	t, err := h.ent.Tenant.Query().
		Where(tenant.SlugEQ(slug)).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get tenant", nil)
		return
	}
	writeJSON(w, http.StatusOK, publicTenantResponseFrom(t))
}

// GetTenantByIDPublic retrieves a tenant by UUID via public endpoint. Mirrors
// GetTenantBySlugPublic but keyed by ID — used by S2S consumers that only carry a
// tenant_id (e.g. notifications-api's event-driven tenant resolver) to dynamically
// sync a local tenant projection without requiring a prior slug lookup.
// No authentication required (same trust boundary as by-slug: non-sensitive fields only).
func (h *AdminHandler) GetTenantByIDPublic(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "tenant_id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}

	t, err := h.ent.Tenant.Query().
		Where(tenant.IDEQ(id)).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get tenant", nil)
		return
	}
	writeJSON(w, http.StatusOK, publicTenantResponseFrom(t))
}

// publicTenantResponseFrom builds the shared public tenant response shape from an ent
// Tenant row. Shared by the by-slug and by-id public lookup endpoints.
func publicTenantResponseFrom(t *ent.Tenant) PublicTenantResponse {
	resp := PublicTenantResponse{
		ID:                    t.ID.String(),
		Name:                  t.Name,
		Slug:                  t.Slug,
		Status:                t.Status,
		IsDemo:                t.IsDemo,
		ContactEmail:          t.ContactEmail,
		ContactPhone:          t.ContactPhone,
		LogoURL:               t.LogoURL,
		Website:               t.Website,
		Country:               t.Country,
		Timezone:              t.Timezone,
		BrandColors:           t.BrandColors,
		OrgSize:               t.OrgSize,
		SubscriptionPlan:      t.SubscriptionPlan,
		SubscriptionStatus:    t.SubscriptionStatus,
		SubscriptionExpiresAt: t.SubscriptionExpiresAt,
		TierLimits:            t.TierLimits,
		Metadata:              t.Metadata,
		TaxPin:                t.TaxPin,
		VatRegistered:         t.VatRegistered,
		VatRegisteredOn:       t.VatRegisteredOn,
	}

	if t.UseCase != nil {
		resp.UseCase = t.UseCase
	}
	if len(t.UseCases) > 0 {
		resp.UseCases = t.UseCases
	}

	return resp
}

func (h *AdminHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	p := pagination.Parse(r)
	search := r.URL.Query().Get("search")
	query := h.ent.Tenant.Query().Where(tenant.StatusEQ("active"))

	if search != "" {
		searchPred := tenant.Or(
			tenant.NameContainsFold(search),
			tenant.SlugContainsFold(search),
		)
		if id, err := uuid.Parse(search); err == nil {
			searchPred = tenant.Or(searchPred, tenant.IDEQ(id))
		}
		query = query.Where(searchPred)
	}

	total, err := query.Count(r.Context())
	if err != nil {
		h.logger.Error("failed to count tenants", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list tenants", nil)
		return
	}
	items, err := query.Order(ent.Asc(tenant.FieldCreatedAt)).Limit(p.Limit).Offset(p.Offset).All(r.Context())
	if err != nil {
		h.logger.Error("failed to list tenants", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list tenants", nil)
		return
	}
	writeJSON(w, http.StatusOK, pagination.NewResponse(items, total, p))
}

func (h *AdminHandler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	idStr := chi.URLParam(r, "tenant_id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}

	var req tenantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	update := h.ent.Tenant.UpdateOneID(id)
	if req.Name != "" {
		update.SetName(req.Name)
	}
	if req.Slug != "" {
		update.SetSlug(req.Slug)
	}
	if req.LogoURL != "" {
		// logo_url has no object-storage backing — it's stored inline as a data
		// URI, so an unbounded upload bloats every /tenants/by-slug response and
		// can crash consumers that embed or cache it (pos-ui, inventory-ui, ...).
		// Validate size and downscale/re-encode oversized images server-side;
		// this is the authoritative check — auth-ui's client-side compression
		// is a UX nicety, not something we can trust alone.
		logoURL, err := imageutil.ValidateAndCompressLogoURL(req.LogoURL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_logo", err.Error(), nil)
			return
		}
		update.SetLogoURL(logoURL)
	}
	if req.Website != "" {
		update.SetWebsite(req.Website)
	}
	if req.BrandColors != nil {
		update.SetBrandColors(req.BrandColors)
	}
	if req.OrgSize != "" {
		update.SetOrgSize(req.OrgSize)
	}
	if req.UseCase != "" {
		update.SetUseCase(req.UseCase)
	}
	if len(req.UseCases) > 0 {
		update.SetUseCases(req.UseCases)
	}
	if req.ContactEmail != "" {
		update.SetContactEmail(req.ContactEmail)
	}
	if req.ContactPhone != "" {
		update.SetContactPhone(req.ContactPhone)
	}
	if req.Country != "" {
		update.SetCountry(req.Country)
	}
	if req.Timezone != "" {
		update.SetTimezone(req.Timezone)
	}

	// Tax / KRA compliance — only touch fields that were explicitly supplied.
	if req.TaxPin != nil {
		if p := strings.TrimSpace(*req.TaxPin); p != "" {
			update.SetTaxPin(p)
		} else {
			update.ClearTaxPin()
		}
	}
	if req.VatRegistered != nil {
		update.SetVatRegistered(*req.VatRegistered)
	}
	if req.IsDemo != nil {
		update.SetIsDemo(*req.IsDemo)
	}
	if req.VatRegisteredOn != nil {
		if d := parseTenantTaxDate(*req.VatRegisteredOn); d != nil {
			update.SetVatRegisteredOn(*d)
		} else {
			update.ClearVatRegisteredOn()
		}
	}

	// Update metadata if provided
	if req.Metadata != nil || req.ContactEmail != "" || req.ContactPhone != "" {
		existing, _ := h.ent.Tenant.Get(r.Context(), id)
		metadata := make(map[string]interface{})
		if existing != nil && existing.Metadata != nil {
			metadata = existing.Metadata
		}
		if req.Metadata != nil {
			for k, v := range req.Metadata {
				// Skip empty string values to avoid overwriting existing metadata
				if str, ok := v.(string); ok && str == "" {
					continue
				}
				metadata[k] = v
			}
		}
		if req.ContactEmail != "" {
			metadata["contact_email"] = req.ContactEmail
		}
		if req.ContactPhone != "" {
			metadata["contact_phone"] = req.ContactPhone
		}
		update.SetMetadata(metadata)
	}

	t, err := update.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update tenant", nil)
		return
	}

	// Re-publish business identity + tax details so treasury-api can re-sync the
	// tenant's invoice issuer block / payment-details config on profile edits.
	actor := ""
	if claims, _ := authmiddleware.ClaimsFromContext(r.Context()); claims != nil {
		actor = claims.Subject
	}
	h.publishTenantLifecycleEvent(r.Context(), t, "updated", actor)

	writeJSON(w, http.StatusOK, t)
}

func (h *AdminHandler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	idStr := chi.URLParam(r, "tenant_id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}

	ctx := r.Context()

	// Delete FK-constrained child records before deleting the tenant.
	if _, err = h.ent.TenantMembership.Delete().
		Where(tenantmembership.TenantID(id)).Exec(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to remove tenant memberships", nil)
		return
	}
	if _, err = h.ent.Outlet.Delete().
		Where(entoutlet.TenantID(id)).Exec(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to remove tenant outlets", nil)
		return
	}

	err = h.ent.Tenant.DeleteOneID(id).Exec(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete tenant", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ProvisionTenantOAuthRedirects ensures the tenant's /{slug}/auth/callback URIs are
// registered on all OAuth clients. Idempotent — safe to call multiple times.
// Called automatically on tenant creation; this endpoint lets admins re-trigger it
// retroactively for tenants that were created before OAuth clients existed.
// POST /api/v1/admin/tenants/{tenant_id}/provision-oauth-redirects
func (h *AdminHandler) ProvisionTenantOAuthRedirects(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	tenantID, err := uuid.Parse(chi.URLParam(r, "tenant_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	t, err := h.ent.Tenant.Get(r.Context(), tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to load tenant", nil)
		}
		return
	}
	if err := auth.AppendTenantRedirectURIs(r.Context(), h.ent, t.Slug); err != nil {
		h.logger.Error("failed to provision tenant redirect URIs",
			zap.String("tenant_slug", t.Slug), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to provision redirect URIs", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "provisioned",
		"slug":    t.Slug,
		"message": fmt.Sprintf("Redirect URIs provisioned for tenant: %s", t.Slug),
	})
}

// Clients
type clientRequest struct {
	ClientID     string   `json:"client_id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Public       bool     `json:"public"`
	TenantID     string   `json:"tenant_id"`
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req clientRequest
	if err := decodeJSON(r, &req); err != nil || req.ClientID == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	create := h.ent.OAuthClient.Create().
		SetClientID(req.ClientID).
		SetName(req.Name).
		SetRedirectUris(req.RedirectURIs).
		SetAllowedScopes(req.Scopes).
		SetPublic(req.Public)
	if req.TenantID != "" {
		create.SetTenantID(req.TenantID)
	}
	c, err := create.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "conflict", "could not create client", nil)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (h *AdminHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	p := pagination.Parse(r)
	q := h.ent.OAuthClient.Query().Where(oauthclient.PublicEQ(true))
	total, err := q.Count(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list clients", nil)
		return
	}
	items, err := q.Limit(p.Limit).Offset(p.Offset).All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list clients", nil)
		return
	}
	writeJSON(w, http.StatusOK, pagination.NewResponse(items, total, p))
}

// GetClient returns a single OAuth client by ID.
func (h *AdminHandler) GetClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "client_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid client id", nil)
		return
	}
	c, err := h.ent.OAuthClient.Get(r.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "client not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to get client", nil)
		}
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// UpdateClient updates an existing OAuth client.
func (h *AdminHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "client_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid client id", nil)
		return
	}
	var req clientRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	update := h.ent.OAuthClient.UpdateOneID(id)
	if req.Name != "" {
		update = update.SetName(req.Name)
	}
	if req.RedirectURIs != nil {
		update = update.SetRedirectUris(req.RedirectURIs)
	}
	if req.Scopes != nil {
		update = update.SetAllowedScopes(req.Scopes)
	}
	update = update.SetPublic(req.Public)
	c, err := update.Save(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "client not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to update client", nil)
		}
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// DeleteClient deletes an OAuth client by ID.
func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "client_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid client id", nil)
		return
	}
	err = h.ent.OAuthClient.DeleteOneID(id).Exec(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "client not found", nil)
		} else {
			writeError(w, http.StatusInternalServerError, "server_error", "failed to delete client", nil)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Key rotation
func (h *AdminHandler) RotateKeys(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	if h.tokens == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "token service not available", nil)
		return
	}
	if err := h.tokens.ReloadFromFiles(); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "reload failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated"})
}

// Entitlements endpoints
type entitlementUpsertRequest struct {
	TenantID    string         `json:"tenant_id"`
	FeatureCode string         `json:"feature_code"`
	Limit       map[string]any `json:"limit"`
	PlanSource  string         `json:"plan_source"`
}

func (h *AdminHandler) UpsertEntitlement(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req entitlementUpsertRequest
	if err := decodeJSON(r, &req); err != nil || req.TenantID == "" || req.FeatureCode == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	tenantID, _ := uuid.Parse(req.TenantID)
	if err := h.entSvc.Upsert(r.Context(), entitlements.Entitlement{
		TenantID:    tenantID,
		FeatureCode: req.FeatureCode,
		Limit:       req.Limit,
		PlanSource:  req.PlanSource,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "upsert failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AdminHandler) ListEntitlements(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	tenantIDStr := r.URL.Query().Get("tenant_id")
	tenantID, _ := uuid.Parse(tenantIDStr)
	items, err := h.entSvc.List(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "list failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// Usage endpoint (increment)
type usageIncRequest struct {
	TenantID string `json:"tenant_id"`
	Type     string `json:"type"`
	Amount   int    `json:"amount"`
}

func (h *AdminHandler) IncrementUsage(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req usageIncRequest
	if err := decodeJSON(r, &req); err != nil || req.TenantID == "" || req.Type == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}
	tenantID, _ := uuid.Parse(req.TenantID)
	var err error
	switch req.Type {
	case "auth_transactions":
		err = h.useSvc.IncrementAuthTransactions(r.Context(), tenantID, req.Amount)
	case "mfa_prompts":
		err = h.useSvc.IncrementMFAPrompts(r.Context(), tenantID, req.Amount)
	default:
		writeError(w, http.StatusBadRequest, "invalid_type", "unsupported usage type", nil)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "increment failed", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Integration Config endpoints
type integrationConfigRequest struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description,omitempty"`
	BaseURL     string            `json:"base_url,omitempty"`
	Credentials map[string]string `json:"credentials"`
	Endpoints   map[string]string `json:"endpoints,omitempty"`
	IsActive    bool              `json:"is_active"`
	Environment string            `json:"environment,omitempty"`
}

type integrationConfigResponse struct {
	ID          string  `json:"id"`
	TenantID    *string `json:"tenant_id,omitempty"`
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Description string  `json:"description,omitempty"`
	IsActive    bool    `json:"is_active"`
	Status      string  `json:"status"`
	Environment string  `json:"environment"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// platformOnlyIntegrations are integrations whose credentials MUST live at
// platform scope (tenant_id = NULL). OAuth identity providers are shared
// infrastructure: all tenants authenticate through the same Google/Microsoft/
// GitHub app, with per-tenant context carried in the OAuth state JWT rather
// than in a per-tenant client_id/secret. Duplicating credentials per tenant
// would also leak secrets across the admin surface — disallow it.
var platformOnlyIntegrations = map[string]bool{
	"google":    true,
	"microsoft": true,
	"github":    true,
	// System keys must also stay platform-wide.
	"system_encryption_key":              true,
	"subscription_api_key":               true,
	platformAlertChannelsIntegrationName: true,
}

func (h *AdminHandler) CreateIntegrationConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}
	var req integrationConfigRequest
	if err := decodeJSON(r, &req); err != nil || req.Name == "" || req.Credentials == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	var tenantID *uuid.UUID
	if req.TenantID != "" {
		tid, err := uuid.Parse(req.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
			return
		}
		tenantID = &tid
	}

	// Enforce platform scope for integrations that are inherently shared.
	// Silently drop the tenant_id instead of erroring — lets the admin UI
	// send the same shape for every provider without having to special-case.
	if platformOnlyIntegrations[req.Name] {
		tenantID = nil
	}

	err := h.integrations.SaveConfig(r.Context(), tenantID, req.Name, req.DisplayName, req.Credentials)
	if err != nil {
		h.logger.Error("Failed to save integration config", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not save config", nil)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (h *AdminHandler) GetIntegrationConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}

	config, err := h.integrations.GetByID(r.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "config not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get config", nil)
		return
	}

	var tidStr *string
	if config.TenantID != nil {
		s := config.TenantID.String()
		tidStr = &s
	}

	writeJSON(w, http.StatusOK, integrationConfigResponse{
		ID:          config.ID.String(),
		TenantID:    tidStr,
		Name:        config.Name,
		DisplayName: config.DisplayName,
		Description: config.Description,
		IsActive:    config.IsActive,
		Status:      config.Status,
		Environment: config.Environment,
		CreatedAt:   config.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   config.UpdatedAt.Format(time.RFC3339),
	})
}

func (h *AdminHandler) ListIntegrationConfigs(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	tenantIDStr := r.URL.Query().Get("tenant_id")
	var tenantID *uuid.UUID
	if tenantIDStr != "" {
		tid, err := uuid.Parse(tenantIDStr)
		if err == nil {
			tenantID = &tid
		}
	}

	configs, err := h.integrations.ListAll(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list configs", nil)
		return
	}

	response := make([]integrationConfigResponse, 0)
	for _, c := range configs {
		var tidStr *string
		if c.TenantID != nil {
			s := c.TenantID.String()
			tidStr = &s
		}
		response = append(response, integrationConfigResponse{
			ID:          c.ID.String(),
			TenantID:    tidStr,
			Name:        c.Name,
			DisplayName: c.DisplayName,
			IsActive:    c.IsActive,
			Status:      c.Status,
			CreatedAt:   c.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   c.UpdatedAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *AdminHandler) DeleteIntegrationConfig(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}

	if err := h.integrations.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete config", nil)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *AdminHandler) UpdateIntegrationStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid id", nil)
		return
	}

	var req struct {
		IsActive bool `json:"is_active"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	if err := h.integrations.UpdateStatus(r.Context(), id, req.IsActive); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to update status", nil)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// platformAlertChannelsIntegrationName is the IntegrationConfig name platform
// admins use (via the existing generic integrations CRUD, POST /admin/integrations)
// to configure where fleet-health-watcher sends alerts — mirrors how OAuth
// provider credentials are already managed, per the 2026-08-16 incident
// follow-up decision to make this admin-UI-configurable rather than a bare
// kubectl-managed secret.
const platformAlertChannelsIntegrationName = "platform_alert_channels"

// S2SPlatformAlertSettings serves GET /api/v1/s2s/platform-alert-settings
// (X-API-Key gated, see requireInternalKey in router.go) for the
// fleet-health-watcher CronJob to fetch the admin-configured Slack webhook
// URL / alert email. Returns an empty object (200) rather than 404 when
// nothing has been configured yet — the caller falls back to its own static
// default in that case, so this is never a hard dependency for alerting to
// work at all.
func (h *AdminHandler) S2SPlatformAlertSettings(w http.ResponseWriter, r *http.Request) {
	creds, err := h.integrations.GetDecryptedConfig(r.Context(), nil, platformAlertChannelsIntegrationName)
	if err != nil {
		// Not configured yet, or decryption unavailable — degrade to empty,
		// never error, so the caller's static fallback still fires.
		writeJSON(w, http.StatusOK, map[string]string{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"slack_webhook_url": creds["slack_webhook_url"],
		"alert_email_to":    creds["alert_email_to"],
	})
}

// Tenant Member Management Endpoints

type addTenantMemberRequest struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email,omitempty"` // alternative to user_id; resolved server-side
	Roles    []string `json:"roles"`
	OutletID string   `json:"outlet_id,omitempty"`
	// Direct-add fields: when email is not an existing user, the account is
	// created on the fly (#3). Name/Phone seed the profile; PIN (4 digits) is
	// optionally provisioned for the given Service (default "pos") so terminal
	// login works immediately and independently of the SSO password.
	Name    string `json:"name,omitempty"`
	Phone   string `json:"phone,omitempty"`
	PIN     string `json:"pin,omitempty"`
	Service string `json:"service,omitempty"`
}

// updateMemberRequest is used by UpdateTenantMember. All fields are optional:
// - roles: only updated when non-empty; omit to leave roles unchanged
// - outlet_id: non-empty UUID sets it; empty string or absent clears it
// - status: non-empty sets the membership status (active|suspended|deactivated)
type updateMemberRequest struct {
	Roles    []string `json:"roles"`
	OutletID *string  `json:"outlet_id"` // pointer: nil = omitted (no change), "" = clear
	Status   string   `json:"status,omitempty"`
}

type tenantMemberResponse struct {
	ID        string   `json:"id"`
	UserID    string   `json:"user_id"`
	TenantID  string   `json:"tenant_id"`
	Roles     []string `json:"roles"`
	Status    string   `json:"status"`
	OutletID  *string  `json:"outlet_id,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
	// TempPassword is returned ONCE when a direct-add created a brand-new account,
	// so the admin can relay it. Never persisted in plaintext, never emailed.
	TempPassword string `json:"temp_password,omitempty"`
}

// AddTenantMember adds a user to a tenant with specified roles.
// POST /api/v1/admin/tenants/{tenant_id}/members
func (h *AdminHandler) AddTenantMember(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	if !h.requireTenantAdmin(r, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return
	}

	var req addTenantMemberRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	// Resolve user: accept either user_id (UUID) or email. For invite/direct-add
	// by email, create the account on the fly when it does not yet exist (#3).
	var userID uuid.UUID
	var tempPassword string // set only when a brand-new account is created
	if req.UserID != "" {
		if id, pErr := uuid.Parse(req.UserID); pErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
			return
		} else {
			userID = id
		}
	} else if req.Email != "" {
		email := strings.ToLower(strings.TrimSpace(req.Email))
		u, uErr := h.ent.User.Query().Where(user.EmailEQ(email)).Only(r.Context())
		if uErr == nil {
			userID = u.ID
		} else if ent.IsNotFound(uErr) {
			// Direct-add: create a new active account with a temporary password.
			// The user must change it on first interactive (SSO) login; a PIN
			// (if provided below) works for terminal login independently.
			tempPassword = generateTempPassword()
			hash, hErr := h.hasher.Hash(tempPassword)
			if hErr != nil {
				h.logger.Error("hash temp password", zap.Error(hErr))
				writeError(w, http.StatusInternalServerError, "server_error", "could not create account", nil)
				return
			}
			profile := map[string]any{"must_change_password": true}
			if strings.TrimSpace(req.Name) != "" {
				profile["name"] = strings.TrimSpace(req.Name)
			}
			if strings.TrimSpace(req.Phone) != "" {
				profile["phone"] = strings.TrimSpace(req.Phone)
			}
			created, cErr := h.ent.User.Create().
				SetEmail(email).
				SetPasswordHash(hash).
				SetStatus("active").
				SetPrimaryTenantID(tenantID.String()).
				SetProfile(profile).
				Save(r.Context())
			if cErr != nil {
				if ent.IsConstraintError(cErr) {
					writeError(w, http.StatusConflict, "conflict", "email already in use", nil)
					return
				}
				h.logger.Error("create direct-add user", zap.Error(cErr))
				writeError(w, http.StatusInternalServerError, "server_error", "could not create account", nil)
				return
			}
			userID = created.ID
		} else {
			writeError(w, http.StatusInternalServerError, "server_error", "user lookup failed", nil)
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id or email is required", nil)
		return
	}

	// Create or update tenant membership
	existingMember, _ := h.ent.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).
		Only(r.Context())

	// Parse optional outlet_id
	var outletID *uuid.UUID
	if req.OutletID != "" {
		if oid, oErr := uuid.Parse(req.OutletID); oErr == nil {
			outletID = &oid
		}
	}

	var membership *ent.TenantMembership
	if existingMember != nil {
		// Update existing
		upd := existingMember.Update().
			SetRoles(req.Roles).
			SetStatus("active")
		if outletID != nil {
			upd = upd.SetOutletID(*outletID)
		}
		membership, err = upd.Save(r.Context())
	} else {
		// Create new
		crt := h.ent.TenantMembership.Create().
			SetUserID(userID).
			SetTenantID(tenantID).
			SetRoles(req.Roles).
			SetStatus("active")
		if outletID != nil {
			crt = crt.SetOutletID(*outletID)
		}
		membership, err = crt.Save(r.Context())
	}

	if err != nil {
		h.logger.Error("Failed to add tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not add member", nil)
		return
	}

	// Publish auth.user.created so downstream services (pos-api, etc.) can provision the user.
	u, userErr := h.ent.User.Get(r.Context(), userID)
	if userErr == nil {
		tenantSlug := ""
		if t, tErr := h.ent.Tenant.Get(r.Context(), tenantID); tErr == nil {
			tenantSlug = t.Slug
		}
		payload := map[string]any{
			"user_id":        userID.String(),
			"email":          u.Email,
			"full_name":      profileStr(u.Profile, "name"),
			"phone":          profileStr(u.Profile, "phone"),
			"tenant_id":      tenantID.String(),
			"tenant_slug":    tenantSlug,
			"roles":          req.Roles,
			"method":         "admin_provisioned",
			"email_verified": u.EmailVerified,
		}
		if outletID != nil {
			payload["outlet_id"] = outletID.String()
		}
		// For brand-new accounts, flag a welcome email with the SSO login link.
		// The plaintext temp password is never emitted — only the login URL is.
		if tempPassword != "" {
			payload["welcome"] = true
			payload["must_change_password"] = true
			payload["login_url"] = h.authUIURL
		}
		h.publishEvent(r.Context(), tenantID, "auth.user", userID, "created", payload)

		// Optionally provision a service PIN so terminal (POS) login works
		// immediately. Mirrors SetUserServicePIN: hash + publish pin_set.
		if req.PIN != "" {
			h.provisionMemberPIN(r.Context(), tenantID, userID, tenantSlug, req.Service, req.PIN, req.Roles, profileStr(u.Profile, "name"), u.Email)
		}
	}

	var outletIDStr *string
	if membership.OutletID != nil {
		s := membership.OutletID.String()
		outletIDStr = &s
	}
	writeJSON(w, http.StatusCreated, tenantMemberResponse{
		ID:           membership.ID.String(),
		UserID:       membership.UserID.String(),
		TenantID:     membership.TenantID.String(),
		Roles:        membership.Roles,
		Status:       membership.Status,
		OutletID:     outletIDStr,
		CreatedAt:    membership.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    membership.UpdatedAt.Format(time.RFC3339),
		TempPassword: tempPassword,
	})
}

// weakServicePINs blocks the handful of trivially guessable 4-digit PINs (every digit the
// same, or a sequential run) for admin/manager-tier staff. PIN uniqueness is enforced only
// PER TENANT, not globally, so two unrelated tenants both defaulting their admin account to
// "1111" means anyone who learns/guesses tenant A's admin PIN can log in as tenant B's admin
// too, by simply trying the same PIN against tenant B's PIN-login endpoint — confirmed live
// against two real production tenants. A 4-digit PIN can't be made unguessable, so the
// practical mitigation is making sure privileged accounts across different tenants don't all
// converge on the same handful of trivial values.
var weakServicePINs = map[string]bool{
	"0000": true, "1111": true, "2222": true, "3333": true, "4444": true,
	"5555": true, "6666": true, "7777": true, "8888": true, "9999": true,
	"0123": true, "1234": true, "2345": true, "3456": true, "4567": true, "5678": true, "6789": true,
	"9876": true, "8765": true, "7654": true, "6543": true, "5432": true, "4321": true, "3210": true,
}

// isAdminOrManagerRole reports whether any of the given (global/service) role names are
// admin/manager tier — the roles whose PIN is worth restricting given the blast radius of a
// cross-tenant collision (full business access vs. a single cashier till).
func isAdminOrManagerRole(roles []string) bool {
	for _, r := range roles {
		switch strings.ToLower(strings.TrimSpace(r)) {
		case "admin", "superuser", "owner", "super_admin", "tenant_admin", "system_admin", "pos_admin", "administrator",
			"manager", "store_manager", "outlet_manager", "supervisor", "inventory_admin", "warehouse_manager":
			return true
		}
	}
	return false
}

// provisionMemberPIN hashes a 4-digit service PIN and publishes auth.user.pin_set
// so downstream services (pos-api etc.) can store the hash. Best-effort: invalid
// PINs are skipped with a warning rather than failing the add. Shared by the
// direct-add flow and SetUserServicePIN.
func (h *AdminHandler) provisionMemberPIN(ctx context.Context, tenantID, userID uuid.UUID, tenantSlug, service, pin string, roles []string, fullName, email string) {
	if len(pin) != 4 {
		h.logger.Warn("skipping PIN provision: pin must be 4 digits")
		return
	}
	for _, ch := range pin {
		if !unicode.IsDigit(ch) {
			h.logger.Warn("skipping PIN provision: pin must be numeric")
			return
		}
	}
	if isAdminOrManagerRole(roles) && weakServicePINs[pin] {
		h.logger.Warn("skipping PIN provision: pin is too common/predictable for an admin/manager role")
		return
	}
	if service == "" {
		service = "pos"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash PIN", zap.Error(err))
		return
	}
	if fullName == "" {
		fullName = email
	}
	h.publishEvent(ctx, tenantID, "auth.user", userID, "pin_set", map[string]any{
		"user_id":     userID.String(),
		"tenant_id":   tenantID.String(),
		"tenant_slug": tenantSlug,
		"service":     service,
		"pin_hash":    string(hash),
		// Raw 4-digit PIN: downstream (pos-api) needs it to compute the user-scoped
		// pin_fast_hash used for terminal fast-login. Without it the consumer stores
		// only pin_hash (no fast_hash) and PIN login silently fails. Internal NATS bus
		// only; the bcrypt hash above is already on the same message.
		"pin":       pin,
		"roles":     roles,
		"full_name": fullName,
	})
}

// ListTenantMembers lists all members of a tenant.
// GET /api/v1/admin/tenants/{tenant_id}/members
// Query params: page, limit, search (email/name), role, status
func (h *AdminHandler) ListTenantMembers(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	if !h.requireTenantAdmin(r, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return
	}

	// Determine whether the requester is a platform owner. Non-platform users
	// must NOT see platform staff (e.g. admin@codevertexafrica.com) even
	// though those accounts hold a membership in every tenant (#1).
	requesterIsPlatform := false
	if claims, ok := authmiddleware.ClaimsFromContext(r.Context()); ok && claims != nil {
		requesterIsPlatform = claims.IsPlatformOwner
	}
	platformTenantID := ""
	if !requesterIsPlatform {
		if pt, ptErr := h.ent.Tenant.Query().Where(tenant.SlugEQ("codevertex")).Only(r.Context()); ptErr == nil {
			platformTenantID = pt.ID.String()
		}
	}

	pg := pagination.Parse(r)
	q := r.URL.Query()
	searchQ := strings.ToLower(strings.TrimSpace(q.Get("search")))
	roleFilter := strings.ToLower(strings.TrimSpace(q.Get("role")))
	statusFilter := strings.TrimSpace(q.Get("status"))

	memberQ := h.ent.TenantMembership.Query().
		Where(tenantmembership.TenantID(tenantID)).
		Order(ent.Asc(tenantmembership.FieldCreatedAt))
	if statusFilter != "" {
		memberQ = memberQ.Where(tenantmembership.StatusEQ(statusFilter))
	}

	// Fetch memberships (with DB-level status filter; role/search need user join so kept in-memory)
	members, err := memberQ.All(r.Context())
	if err != nil {
		h.logger.Error("Failed to list tenant members", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not list members", nil)
		return
	}

	// Batch fetch user details to avoid N+1
	userIDs := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		userIDs = append(userIDs, m.UserID)
	}
	userMap := make(map[uuid.UUID]*ent.User)
	if len(userIDs) > 0 {
		users, uErr := h.ent.User.Query().
			Where(user.IDIn(userIDs...)).
			All(r.Context())
		if uErr != nil {
			h.logger.Warn("Failed to batch-fetch users for member list", zap.Error(uErr))
		}
		for _, u := range users {
			userMap[u.ID] = u
		}
	}

	// Build enriched entries and apply in-memory filters
	type memberEntry struct {
		ID        string   `json:"id"`
		UserID    string   `json:"user_id"`
		TenantID  string   `json:"tenant_id"`
		Roles     []string `json:"roles"`
		Status    string   `json:"status"`
		OutletID  *string  `json:"outlet_id,omitempty"`
		Email     string   `json:"email,omitempty"`
		Name      string   `json:"name,omitempty"`
		AvatarURL string   `json:"avatar_url,omitempty"`
		CreatedAt string   `json:"created_at"`
		UpdatedAt string   `json:"updated_at"`
	}

	all := make([]memberEntry, 0, len(members))
	for _, m := range members {
		// Hide platform staff from non-platform requesters (#1): any member whose
		// primary tenant is the platform ("codevertex") tenant is platform staff.
		if platformTenantID != "" {
			if u, ok := userMap[m.UserID]; ok && u.PrimaryTenantID == platformTenantID {
				continue
			}
		}

		roles := m.Roles
		if roles == nil {
			roles = []string{"member"}
		}
		var outletIDStr *string
		if m.OutletID != nil {
			s := m.OutletID.String()
			outletIDStr = &s
		}
		entry := memberEntry{
			ID:        m.ID.String(),
			UserID:    m.UserID.String(),
			TenantID:  m.TenantID.String(),
			Roles:     roles,
			Status:    m.Status,
			OutletID:  outletIDStr,
			CreatedAt: m.CreatedAt.Format(time.RFC3339),
			UpdatedAt: m.UpdatedAt.Format(time.RFC3339),
		}
		if u, ok := userMap[m.UserID]; ok {
			entry.Email = u.Email
			if u.Profile != nil {
				if v, ok := u.Profile["name"].(string); ok && v != "" {
					entry.Name = v
				} else if v, ok := u.Profile["full_name"].(string); ok && v != "" {
					entry.Name = v
				}
				if v, ok := u.Profile["avatar_url"].(string); ok {
					entry.AvatarURL = v
				}
			}
		}

		// Apply in-memory filters (role, search — require user join for DB-level)
		if roleFilter != "" {
			found := false
			for _, r := range roles {
				if strings.ToLower(r) == roleFilter {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if searchQ != "" {
			emailMatch := strings.Contains(strings.ToLower(entry.Email), searchQ)
			nameMatch := strings.Contains(strings.ToLower(entry.Name), searchQ)
			if !emailMatch && !nameMatch {
				continue
			}
		}

		all = append(all, entry)
	}

	// Paginate using shared library offsets
	total := len(all)
	start := pg.Offset
	end := start + pg.Limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	writeJSON(w, http.StatusOK, pagination.NewResponse(all[start:end], total, pg))
}

// S2SListTenantUsers lists a tenant's active members for service-to-service callers.
// GET /api/v1/s2s/{tenant}/users  (auth: INTERNAL_SERVICE_KEY via X-API-Key middleware)
//
// {tenant} accepts either the tenant UUID or its slug. Returns active memberships only,
// as [{id,email,name,roles,outlet_id}] where id is the auth user id. Reuses the same
// TenantMembership + User read path as the JWT-admin ListTenantMembers. erp-api's
// employee backfill consumes this to project auth users into employees.
// S2SUserEmailVerification returns the computed email-verification enforcement state for a
// user (verified, is_placeholder, strict, stage, days_until_disable, wait_seconds, ...) so a
// downstream service's /auth/me can forward the SAME block auth-api's own /me returns, giving
// every frontend an identical graduated verify banner. Gated by INTERNAL_SERVICE_KEY.
// GET /api/v1/s2s/users/{user_id}/email-verification
func (h *AdminHandler) S2SUserEmailVerification(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "user_id")))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}
	u, err := h.ent.User.Get(r.Context(), userID)
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "user not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "could not load user", nil)
		return
	}
	// Start the clock on first exposure (via any service), same as auth-api's own /me.
	if !u.EmailVerified && u.EmailVerificationRequiredAt == nil {
		if updated, uerr := u.Update().SetEmailVerificationRequiredAt(time.Now()).Save(r.Context()); uerr == nil {
			u = updated
		}
	}

	// Union the user's roles across ALL active memberships: strict enforcement applies if
	// the user holds a notification-bearing role in ANY tenant.
	var roles []string
	if memberships, mErr := h.ent.TenantMembership.Query().
		Where(tenantmembership.UserID(userID), tenantmembership.StatusEQ("active")).
		All(r.Context()); mErr == nil {
		seen := map[string]bool{}
		for _, m := range memberships {
			for _, role := range m.Roles {
				if role != "" && !seen[role] {
					seen[role] = true
					roles = append(roles, role)
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, auth.EmailVerificationStateFor(u, roles, time.Now()))
}

func (h *AdminHandler) S2SListTenantUsers(w http.ResponseWriter, r *http.Request) {
	tenantRef := strings.TrimSpace(chi.URLParam(r, "tenant"))
	if tenantRef == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "tenant is required", nil)
		return
	}

	// Resolve {tenant} as a UUID first, then fall back to slug.
	var t *ent.Tenant
	if tid, err := uuid.Parse(tenantRef); err == nil {
		t, err = h.ent.Tenant.Get(r.Context(), tid)
		if err != nil && !ent.IsNotFound(err) {
			h.logger.Error("S2S list users: get tenant by id", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "could not resolve tenant", nil)
			return
		}
	}
	if t == nil {
		tt, err := h.ent.Tenant.Query().Where(tenant.SlugEQ(tenantRef)).Only(r.Context())
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
			return
		}
		if err != nil {
			h.logger.Error("S2S list users: get tenant by slug", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "server_error", "could not resolve tenant", nil)
			return
		}
		t = tt
	}

	members, err := h.ent.TenantMembership.Query().
		Where(
			tenantmembership.TenantID(t.ID),
			tenantmembership.StatusEQ("active"),
		).
		Order(ent.Asc(tenantmembership.FieldCreatedAt)).
		All(r.Context())
	if err != nil {
		h.logger.Error("S2S list users: query memberships", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not list users", nil)
		return
	}

	userIDs := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		userIDs = append(userIDs, m.UserID)
	}
	userMap := make(map[uuid.UUID]*ent.User, len(userIDs))
	if len(userIDs) > 0 {
		users, uErr := h.ent.User.Query().Where(user.IDIn(userIDs...)).All(r.Context())
		if uErr != nil {
			h.logger.Error("S2S list users: batch-fetch users", zap.Error(uErr))
			writeError(w, http.StatusInternalServerError, "server_error", "could not list users", nil)
			return
		}
		for _, u := range users {
			userMap[u.ID] = u
		}
	}

	type s2sUser struct {
		ID       string   `json:"id"`
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Roles    []string `json:"roles"`
		OutletID *string  `json:"outlet_id,omitempty"`
	}
	out := make([]s2sUser, 0, len(members))
	for _, m := range members {
		roles := m.Roles
		if roles == nil {
			roles = []string{"member"}
		}
		var outletIDStr *string
		if m.OutletID != nil {
			s := m.OutletID.String()
			outletIDStr = &s
		}
		entry := s2sUser{ID: m.UserID.String(), Roles: roles, OutletID: outletIDStr}
		if u, ok := userMap[m.UserID]; ok {
			entry.Email = u.Email
			if u.Profile != nil {
				if v, ok := u.Profile["name"].(string); ok && v != "" {
					entry.Name = v
				} else if v, ok := u.Profile["full_name"].(string); ok && v != "" {
					entry.Name = v
				}
			}
		}
		out = append(out, entry)
	}

	writeJSON(w, http.StatusOK, out)
}

// UpdateTenantMember updates a member's roles.
// PUT /api/v1/admin/tenants/{tenant_id}/members/{user_id}
func (h *AdminHandler) UpdateTenantMember(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenant_id")
	userIDStr := chi.URLParam(r, "user_id")

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	if !h.requireTenantAdmin(r, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}

	var req updateMemberRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	membership, err := h.ent.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "member not found", nil)
			return
		}
		h.logger.Error("Failed to find tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not find member", nil)
		return
	}

	upd := membership.Update()
	// Only overwrite roles when the caller explicitly supplies them.
	if len(req.Roles) > 0 {
		upd = upd.SetRoles(req.Roles)
	}
	// Tenant-scoped lifecycle: suspend/activate/deactivate a member (#3). This is
	// distinct from the platform-wide user.status managed by platform admins.
	if req.Status != "" {
		switch req.Status {
		case "active", "suspended", "deactivated", "inactive":
			upd = upd.SetStatus(req.Status)
		default:
			writeError(w, http.StatusBadRequest, "invalid_request", "status must be active, suspended, deactivated or inactive", nil)
			return
		}
	}
	var outletIDPtr *uuid.UUID
	if req.OutletID != nil {
		if *req.OutletID == "" {
			// Explicit empty string → clear outlet assignment.
			upd = upd.ClearOutletID()
		} else if oid, oErr := uuid.Parse(*req.OutletID); oErr == nil {
			upd = upd.SetOutletID(oid)
			outletIDPtr = &oid
		}
	}
	updated, err := upd.Save(r.Context())
	if err != nil {
		h.logger.Error("Failed to update tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not update member", nil)
		return
	}

	// Publish auth.user.updated so downstream services can sync role/outlet changes.
	eventPayload := map[string]any{
		"user_id":   userID.String(),
		"tenant_id": tenantID.String(),
		"roles":     updated.Roles,
	}
	if outletIDPtr != nil {
		eventPayload["outlet_id"] = outletIDPtr.String()
	}
	h.publishEvent(r.Context(), tenantID, "auth.user", userID, "updated", eventPayload)

	var outletIDStr *string
	if updated.OutletID != nil {
		s := updated.OutletID.String()
		outletIDStr = &s
	}
	writeJSON(w, http.StatusOK, tenantMemberResponse{
		ID:        updated.ID.String(),
		UserID:    updated.UserID.String(),
		TenantID:  updated.TenantID.String(),
		Roles:     updated.Roles,
		Status:    updated.Status,
		OutletID:  outletIDStr,
		CreatedAt: updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt: updated.UpdatedAt.Format(time.RFC3339),
	})
}

// RemoveTenantMember removes a user from a tenant.
// DELETE /api/v1/admin/tenants/{tenant_id}/members/{user_id}
func (h *AdminHandler) RemoveTenantMember(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenant_id")
	userIDStr := chi.URLParam(r, "user_id")

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	if !h.requireTenantAdmin(r, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}

	_, err = h.ent.TenantMembership.Delete().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).
		Exec(r.Context())
	if err != nil {
		h.logger.Error("Failed to remove tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not remove member", nil)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// profileStr extracts a string value from a user's Profile JSON map.
func profileStr(profile map[string]any, key string) string {
	if profile == nil {
		return ""
	}
	v, _ := profile[key].(string)
	return v
}

type setUserServicePINRequest struct {
	Service string `json:"service"`
	PIN     string `json:"pin"`
}

// SetUserServicePIN allows tenant admins to set a service-level PIN for a user.
// POST /api/v1/admin/tenants/{tenant_id}/members/{user_id}/service-pin
// Publishes auth.user.pin_set so downstream services (pos-api etc.) can store the PIN hash.
func (h *AdminHandler) SetUserServicePIN(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "tenant_id")
	userIDStr := chi.URLParam(r, "user_id")

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}
	if !h.requireTenantAdmin(r, tenantID) {
		writeError(w, http.StatusForbidden, "forbidden", "tenant admin required", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}

	var req setUserServicePINRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid payload", nil)
		return
	}

	// Validate PIN: must be exactly 4 digits.
	if len(req.PIN) != 4 {
		writeError(w, http.StatusBadRequest, "invalid_request", "pin must be exactly 4 digits", nil)
		return
	}
	for _, ch := range req.PIN {
		if !unicode.IsDigit(ch) {
			writeError(w, http.StatusBadRequest, "invalid_request", "pin must be numeric", nil)
			return
		}
	}

	if req.Service == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "service is required", nil)
		return
	}

	// Verify user exists in this tenant and fetch their roles.
	membership, err := h.ent.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).
		Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "member not found", nil)
			return
		}
		h.logger.Error("Failed to find tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not verify member", nil)
		return
	}

	// Admin/manager PINs are a much higher-value target than a cashier's — a collision with
	// another tenant's admin PIN grants full cross-tenant business access (confirmed live), so
	// these roles may not use a trivially guessable PIN.
	if isAdminOrManagerRole(membership.Roles) && weakServicePINs[req.PIN] {
		writeError(w, http.StatusBadRequest, "invalid_request", "this PIN is too common for an admin/manager account — choose a less predictable 4-digit PIN", nil)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.PIN), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash PIN", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not hash pin", nil)
		return
	}

	// Resolve the user's display name for pos-api StaffMember creation.
	fullName := ""
	if u, uErr := h.ent.User.Get(r.Context(), userID); uErr == nil {
		fullName = profileStr(u.Profile, "name")
		if fullName == "" {
			fullName = profileStr(u.Profile, "full_name")
		}
		if fullName == "" {
			fullName = u.Email
		}
	}

	// Resolve tenant slug so downstream services (pos-api) can sync tenant + outlets
	// on demand without a separate lookup.
	tenantSlug := ""
	if t, tErr := h.ent.Tenant.Get(r.Context(), tenantID); tErr == nil {
		tenantSlug = t.Slug
	}

	h.publishEvent(r.Context(), tenantID, "auth.user", userID, "pin_set", map[string]any{
		"user_id":     userID.String(),
		"tenant_id":   tenantID.String(),
		"tenant_slug": tenantSlug,
		"service":     req.Service,
		"pin_hash":    string(hash),
		// Raw PIN so pos-api can compute the user-scoped pin_fast_hash for terminal
		// fast-login (pin_hash alone leaves fast_hash NULL and login fails).
		"pin":       req.PIN,
		"roles":     membership.Roles,
		"full_name": fullName,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "pin_set"})
}
