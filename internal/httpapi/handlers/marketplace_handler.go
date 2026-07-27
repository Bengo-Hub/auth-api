package handlers

import (
	"net/http"
	"sort"
	"strings"

	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/Bengo-Hub/pagination"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"go.uber.org/zap"
)

// marketplaceHardCap bounds how many active, non-demo, non-platform-owner tenant
// rows this endpoint will ever load from the DB before ranking + paginating in Go.
// The marketplace is inherently small (real paying customers only, one row per
// tenant), so this is a generous safety ceiling rather than an expected size.
const marketplaceHardCap = 1000

// planTierRank maps the LAST "_"-delimited segment of a subscription_plan code to a
// numeric tier rank used to sort the marketplace (higher rank = shown first).
//
// subscription_plan is a free-form code synced 1:1 from subscriptions-api's
// tenant.subscription.updated event (see internal/platform/events/subscription_subscriber.go,
// which just does upd.SetSubscriptionPlan(newPlanCode) with no validation). Verified the
// actual values it takes by grepping subscriptions-api's plan catalogue
// (subscriptions-service/subscriptions-api/cmd/seed/plans_*.go and bundles.go):
// every product family (ORDERING_, TREASURY_, INVENTORY_, MARKETFLOW_, PROJECTS_,
// TRULOAD_, LOGISTICS_, LIBRARY_, ISP_BILLING_, ERP_) follows a "<PRODUCT>_<TIER>"
// naming convention with a shared tier vocabulary, and the PowerSuite family
// (POWERSUITE_HOSP_/DUKA_/DAWA_) follows "<FAMILY>_<VERTICAL>_<TIER>". auth-api's own
// trial default (internal/services/auth/service.go defaultTrialPlan) also emits bare
// "STARTER". Rather than hardcode every full plan code combination (10+ product
// families × tiers), rank by the shared trailing tier keyword, which is stable
// across all of them.
var planTierRank = map[string]int{
	"STARTER":      1,
	"BASIC":        1,
	"GROWTH":       2,
	"STANDARD":     2,
	"PRO":          2,
	"PROFESSIONAL": 3,
	"GOLD":         3,
	"PREMIUM":      3,
	"ENTERPRISE":   4,
	"LICENSE":      4,
	"CUSTOM":       4,
}

// planRank returns the numeric tier rank for a subscription_plan code, using the
// trailing "_"-delimited segment (e.g. "POWERSUITE_HOSP_GOLD" -> "GOLD" -> 3).
// Unknown/unset codes rank lowest (0) so they sort after all recognised tiers.
func planRank(planCode *string) int {
	if planCode == nil || *planCode == "" {
		return 0
	}
	code := *planCode
	if idx := strings.LastIndex(code, "_"); idx >= 0 {
		code = code[idx+1:]
	}
	return planTierRank[strings.ToUpper(code)]
}

// MarketplaceTenant is the public, non-sensitive response shape for one tenant row
// in the marketplace listing. Field allowlist mirrors PublicTenantResponse (the
// shape already considered safe-for-public by GetTenantBySlugPublic/GetTenantByIDPublic)
// — deliberately excludes contact_email, contact_phone, tax_pin, vat_registered,
// metadata, tier_limits, and any other internal/sensitive field.
type MarketplaceTenant struct {
	ID               string         `json:"id"`
	Slug             string         `json:"slug"`
	Name             string         `json:"name"`
	LogoURL          *string        `json:"logo_url,omitempty"`
	BrandColors      map[string]any `json:"brand_colors,omitempty"`
	UseCase          *string        `json:"use_case,omitempty"`
	UseCases         []string       `json:"use_cases,omitempty"`
	SubscriptionPlan *string        `json:"subscription_plan,omitempty"`
	Country          *string        `json:"country,omitempty"`
}

// ListMarketplaceTenants handles GET /api/v1/tenants/marketplace.
//
// Public, no authentication required — same trust tier as GetTenantBySlugPublic/
// GetTenantByIDPublic (non-sensitive fields only, just for many tenants at once).
// Powers a cross-tenant "marketplace landing page" (e.g. an ordering-backend
// storefront directory) that lists real, live customer tenants ranked by
// subscription tier.
//
// Filtering (mandatory):
//   - status = "active" only
//   - is_demo = false only (a live customer-facing marketplace must never show demo tenants)
//   - excludes the platform-owner's own internal tenant (slug == platformTenantSlug,
//     the same "codevertex" check already used elsewhere in this package, e.g.
//     oidc_handler.go and services/auth/service.go, for "is this the platform's own tenant")
//   - optional ?use_case= filters on the legacy single use_case field OR containment
//     in the use_cases[] JSON array
//
// Sorting: higher subscription tier first (see planTierRank), then by created_at
// as a stable tiebreaker.
//
// ListMarketplaceTenants godoc
// @Summary List active, non-demo tenants for the cross-tenant marketplace (public)
// @Description Returns a paginated, safe-fields-only tenant listing ranked by subscription tier, for cross-tenant marketplace/landing-page use cases. No authentication required.
// @Tags tenants/public
// @Produce json
// @Param use_case query string false "Filter by use_case (matches legacy use_case field or containment in use_cases[])"
// @Param page query int false "Page number (1-based)"
// @Param limit query int false "Page size (default 20, max 100)"
// @Success 200 {object} pagination.Response[MarketplaceTenant]
// @Router /api/v1/tenants/marketplace [get]
func (h *AdminHandler) ListMarketplaceTenants(w http.ResponseWriter, r *http.Request) {
	p := pagination.Parse(r)
	useCase := strings.TrimSpace(r.URL.Query().Get("use_case"))

	query := h.ent.Tenant.Query().Where(
		tenant.StatusEQ("active"),
		tenant.IsDemoEQ(false),
		tenant.SlugNEQ(platformTenantSlug),
	)

	if useCase != "" {
		query = query.Where(tenant.Or(
			tenant.UseCaseEqualFold(useCase),
			func(s *entsql.Selector) {
				s.Where(sqljson.ValueContains(tenant.FieldUseCases, useCase))
			},
		))
	}

	// Load the full (already filtered-down-to-real-customers) matching set, ranked
	// in Go rather than via a fragile SQL CASE expression — this is a small, capped
	// listing (marketplaceHardCap), not the entire tenant table, so a single fetch
	// keeps tier ranking correct across page boundaries.
	all, err := query.Order(ent.Asc(tenant.FieldCreatedAt)).Limit(marketplaceHardCap).All(r.Context())
	if err != nil {
		h.logger.Error("failed to list marketplace tenants", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list tenants", nil)
		return
	}

	sort.SliceStable(all, func(i, j int) bool {
		return planRank(all[i].SubscriptionPlan) > planRank(all[j].SubscriptionPlan)
	})

	total := len(all)
	start := p.Offset
	if start > total {
		start = total
	}
	end := start + p.Limit
	if end > total {
		end = total
	}
	page := all[start:end]

	items := make([]MarketplaceTenant, 0, len(page))
	for _, t := range page {
		mt := MarketplaceTenant{
			ID:               t.ID.String(),
			Slug:             t.Slug,
			Name:             t.Name,
			LogoURL:          t.LogoURL,
			BrandColors:      t.BrandColors,
			SubscriptionPlan: t.SubscriptionPlan,
			Country:          t.Country,
		}
		if t.UseCase != nil {
			mt.UseCase = t.UseCase
		}
		if len(t.UseCases) > 0 {
			mt.UseCases = t.UseCases
		}
		items = append(items, mt)
	}

	writeJSON(w, http.StatusOK, pagination.NewResponse(items, total, p))
}
