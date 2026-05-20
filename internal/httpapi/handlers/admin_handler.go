package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/services/auth"
	"github.com/bengobox/auth-api/internal/services/entitlements"
	"github.com/bengobox/auth-api/internal/services/integrations"
	"github.com/bengobox/auth-api/internal/services/usage"
	"github.com/bengobox/auth-api/internal/token"
	subscriptionclient "github.com/bengobox/auth-api/internal/clients/subscription"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AdminHandler provides basic tenant/client admin APIs.
type AdminHandler struct {
	ent    *ent.Client
	logger *zap.Logger
	entSvc *entitlements.Service
	useSvc *usage.Service
	tokens       *token.Service
	integrations *integrations.Service
	subClient    *subscriptionclient.Client
}

func NewAdminHandler(entClient *ent.Client, tokens *token.Service, integrationSvc *integrations.Service, subClient *subscriptionclient.Client, logger *zap.Logger) *AdminHandler {
	return &AdminHandler{
		ent:          entClient,
		logger:       logger,
		entSvc:       entitlements.New(entClient),
		useSvc:       usage.New(entClient),
		tokens:       tokens,
		integrations: integrationSvc,
		subClient:    subClient,
	}
}

func (h *AdminHandler) requireAdmin(r *http.Request) bool {
	claims, ok := authmiddleware.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return false
	}

	// Platform owners (primary tenant = "codevertex") bypass all RBAC.
	if claims.IsPlatformOwner {
		return true
	}

	// Superuser / admin roles from TenantMembership. Accept "admin" too —
	// a tenant admin managing their own org's settings should pass, and
	// cross-tenant writes are already gated by tenant_id checks on the
	// targeted entity.
	for _, role := range claims.Roles {
		if role == "superuser" || role == "admin" {
			return true
		}
	}

	// Explicit admin scopes (for service-to-service tokens).
	for _, s := range claims.Scope {
		if s == "admin" || s == "auth.admin" {
			return true
		}
	}
	return false
}

// publishTenantEvent writes a tenant.created event to the outbox for async NATS publishing.
func (h *AdminHandler) publishEvent(ctx context.Context, tenantID uuid.UUID, aggregateType string, aggregateID uuid.UUID, eventType string, data map[string]any) {
	event := sharedevents.Event{
		ID:            uuid.New(),
		TenantID:      tenantID,
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		EventType:     eventType,
		Payload:       data,
		Timestamp:    time.Now().UTC(),
		Version:      "1.0",
	}

	payload, err := json.Marshal(event)
	if err != nil {
		h.logger.Warn("failed to marshal event", zap.Error(err), zap.String("event_type", eventType))
		return
	}

	err = h.ent.OutboxEvent.Create().
		SetTenantID(tenantID).
		SetAggregateType(aggregateType).
		SetAggregateID(aggregateID).
		SetEventType(eventType).
		SetPayload(payload).
		SetStatus(outboxevent.StatusPENDING).
		SetAttempts(0).
		Exec(ctx)
	if err != nil {
		h.logger.Warn("failed to write outbox event", zap.Error(err), zap.String("event_type", eventType))
	}
}

func (h *AdminHandler) publishTenantEvent(ctx context.Context, tenantID uuid.UUID, name, slug, useCase, createdBy string) {
	h.publishEvent(ctx, tenantID, "auth.tenant", tenantID, "created", map[string]any{
		"tenant_id":  tenantID.String(),
		"name":       name,
		"slug":       slug,
		"use_case":   useCase,
		"created_by": createdBy,
	})
}

// Tenants — accepts every field the tenant entity can carry so the frontend
// can POST/PUT a full tenant object without triggering DisallowUnknownFields.
// Fields the update handler ignores (status, subscription_*) are read-only.
type tenantRequest struct {
	ID               string                 `json:"id,omitempty"`
	Name             string                 `json:"name"`
	Slug             string                 `json:"slug"`
	Status           string                 `json:"status,omitempty"` // read-only; ignored on update
	UseCase          string                 `json:"use_case,omitempty"`
	UseCases         []string               `json:"use_cases,omitempty"`
	ContactEmail     string                 `json:"contact_email,omitempty"`
	ContactPhone     string                 `json:"contact_phone,omitempty"`
	SubscriptionPlan string                 `json:"subscription_plan,omitempty"`
	SubscriptionStatus string               `json:"subscription_status,omitempty"`
	SubscriptionExpiresAt *string            `json:"subscription_expires_at,omitempty"`
	HQBranchName     string                 `json:"hq_branch_name,omitempty"`
	LogoURL          string                 `json:"logo_url,omitempty"`
	Website          string                 `json:"website,omitempty"`
	BrandColors      map[string]any         `json:"brand_colors,omitempty"`
	OrgSize          string                 `json:"org_size,omitempty"`
	Country          string                 `json:"country,omitempty"`
	Timezone         string                 `json:"timezone,omitempty"`
	TierLimits       map[string]any         `json:"tier_limits,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt        *string                `json:"created_at,omitempty"`
	UpdatedAt        *string                `json:"updated_at,omitempty"`
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
		sub, err := h.subClient.CreateTrialSubscription(r.Context(), t.ID, plan)
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
	h.publishTenantEvent(r.Context(), t.ID, t.Name, t.Slug, useCase, createdBy)

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
			"outlet_id":  hqOutlet.ID.String(),
			"tenant_id":  t.ID.String(),
			"code":       hqOutlet.Code,
			"name":       hqOutlet.Name,
			"use_case":   hqOutlet.UseCase,
			"is_hq":      hqOutlet.IsHq,
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

// CreateTenantPublic creates a tenant via public endpoint (for tenant auto-discovery).
// This endpoint does not require authentication and is used by services to sync tenants.
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
		sub, err := h.subClient.CreateTrialSubscription(r.Context(), t.ID, plan)
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
	h.publishTenantEvent(r.Context(), t.ID, t.Name, t.Slug, useCase, "self-service")

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
			"outlet_id":  hqOutletPub.ID.String(),
			"tenant_id":  t.ID.String(),
			"code":       hqOutletPub.Code,
			"name":       hqOutletPub.Name,
			"use_case":   hqOutletPub.UseCase,
			"is_hq":      hqOutletPub.IsHq,
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
	resp := PublicTenantResponse{
		ID:                    t.ID.String(),
		Name:                  t.Name,
		Slug:                  t.Slug,
		Status:                t.Status,
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
	}

	if t.UseCase != nil {
		resp.UseCase = t.UseCase
	}
	if len(t.UseCases) > 0 {
		resp.UseCases = t.UseCases
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	search := r.URL.Query().Get("search")
	query := h.ent.Tenant.Query().Where(tenant.StatusEQ("active"))

	if search != "" {
		// Case-insensitive search on name, slug or ID
		query = query.Where(
			tenant.Or(
				tenant.NameContainsFold(search),
				tenant.SlugContainsFold(search),
			),
		)
		// If it's a valid UUID, search by ID as well
		if id, err := uuid.Parse(search); err == nil {
			query = query.Where(tenant.IDEQ(id))
		}
	}

	items, err := query.All(r.Context())
	if err != nil {
		h.logger.Error("failed to list tenants", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list tenants", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
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
		update.SetLogoURL(req.LogoURL)
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

	// Soft delete by setting status to 'deleted' or actually deleting
	// For now, let's just delete
	err = h.ent.Tenant.DeleteOneID(id).Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to delete tenant", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
	items, err := h.ent.OAuthClient.Query().Where(oauthclient.PublicEQ(true)).All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list clients", nil)
		return
	}
	writeJSON(w, http.StatusOK, items)
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
	TenantID            string            `json:"tenant_id,omitempty"`
	Name                string            `json:"name"`
	DisplayName         string            `json:"display_name"`
	Description         string            `json:"description,omitempty"`
	BaseURL             string            `json:"base_url,omitempty"`
	Credentials         map[string]string `json:"credentials"`
	Endpoints           map[string]string `json:"endpoints,omitempty"`
	IsActive            bool              `json:"is_active"`
	Environment         string            `json:"environment,omitempty"`
}

type integrationConfigResponse struct {
	ID          string            `json:"id"`
	TenantID    *string           `json:"tenant_id,omitempty"`
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Description string            `json:"description,omitempty"`
	IsActive    bool              `json:"is_active"`
	Status      string            `json:"status"`
	Environment string            `json:"environment"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
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
	"system_encryption_key": true,
	"subscription_api_key":  true,
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

// Tenant Member Management Endpoints

type addTenantMemberRequest struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

type tenantMemberResponse struct {
	ID        string   `json:"id"`
	UserID    string   `json:"user_id"`
	TenantID  string   `json:"tenant_id"`
	Roles     []string `json:"roles"`
	Status    string   `json:"status"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// AddTenantMember adds a user to a tenant with specified roles.
// POST /api/v1/admin/tenants/{tenant_id}/members
func (h *AdminHandler) AddTenantMember(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	tenantIDStr := chi.URLParam(r, "tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}

	var req addTenantMemberRequest
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id is required", nil)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}

	// Create or update tenant membership
	existingMember, _ := h.ent.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).
		Only(r.Context())

	var membership *ent.TenantMembership
	if existingMember != nil {
		// Update existing
		membership, err = existingMember.Update().
			SetRoles(req.Roles).
			SetStatus("active").
			Save(r.Context())
	} else {
		// Create new
		membership, err = h.ent.TenantMembership.Create().
			SetUserID(userID).
			SetTenantID(tenantID).
			SetRoles(req.Roles).
			SetStatus("active").
			Save(r.Context())
	}

	if err != nil {
		h.logger.Error("Failed to add tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not add member", nil)
		return
	}

	writeJSON(w, http.StatusCreated, tenantMemberResponse{
		ID:        membership.ID.String(),
		UserID:    membership.UserID.String(),
		TenantID:  membership.TenantID.String(),
		Roles:     membership.Roles,
		Status:    membership.Status,
		CreatedAt: membership.CreatedAt.Format(time.RFC3339),
		UpdatedAt: membership.UpdatedAt.Format(time.RFC3339),
	})
}

// ListTenantMembers lists all members of a tenant.
// GET /api/v1/admin/tenants/{tenant_id}/members
func (h *AdminHandler) ListTenantMembers(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	tenantIDStr := chi.URLParam(r, "tenant_id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}

	members, err := h.ent.TenantMembership.Query().
		Where(tenantmembership.TenantID(tenantID)).
		All(r.Context())
	if err != nil {
		h.logger.Error("Failed to list tenant members", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not list members", nil)
		return
	}

	// Collect user IDs for batch lookup
	userIDs := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		userIDs = append(userIDs, m.UserID)
	}

	// Batch fetch user details (email, profile) to avoid N+1 queries
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

	response := make([]map[string]interface{}, 0)
	for _, member := range members {
		entry := map[string]interface{}{
			"id":         member.ID.String(),
			"user_id":    member.UserID.String(),
			"tenant_id":  member.TenantID.String(),
			"roles":      member.Roles,
			"status":     member.Status,
			"created_at": member.CreatedAt.Format(time.RFC3339),
			"updated_at": member.UpdatedAt.Format(time.RFC3339),
		}
		// Enrich with user details if available
		if u, ok := userMap[member.UserID]; ok {
			entry["email"] = u.Email
			if u.Profile != nil {
				if name, ok := u.Profile["name"]; ok {
					entry["name"] = name
				} else if fullName, ok := u.Profile["full_name"]; ok {
					entry["name"] = fullName
				}
			}
		}
		response = append(response, entry)
	}

	writeJSON(w, http.StatusOK, response)
}

// UpdateTenantMember updates a member's roles.
// PUT /api/v1/admin/tenants/{tenant_id}/members/{user_id}
func (h *AdminHandler) UpdateTenantMember(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	tenantIDStr := chi.URLParam(r, "tenant_id")
	userIDStr := chi.URLParam(r, "user_id")

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id", nil)
		return
	}

	var req addTenantMemberRequest
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

	updated, err := membership.Update().
		SetRoles(req.Roles).
		Save(r.Context())
	if err != nil {
		h.logger.Error("Failed to update tenant member", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "could not update member", nil)
		return
	}

	writeJSON(w, http.StatusOK, tenantMemberResponse{
		ID:        updated.ID.String(),
		UserID:    updated.UserID.String(),
		TenantID:  updated.TenantID.String(),
		Roles:     updated.Roles,
		Status:    updated.Status,
		CreatedAt: updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt: updated.UpdatedAt.Format(time.RFC3339),
	})
}

// RemoveTenantMember removes a user from a tenant.
// DELETE /api/v1/admin/tenants/{tenant_id}/members/{user_id}
func (h *AdminHandler) RemoveTenantMember(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "admin scope required", nil)
		return
	}

	tenantIDStr := chi.URLParam(r, "tenant_id")
	userIDStr := chi.URLParam(r, "user_id")

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid tenant_id", nil)
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
