package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Tenant holds the schema definition for the Tenant entity.
// This is the source of truth for all tenant identities in the BengoBox platform.
// Every other service that integrates with SSO must sync tenant data from auth-api
// using the public GET /api/v1/tenants/by-slug/{slug} endpoint to obtain the real UUID.
type Tenant struct {
	ent.Schema
}

// Fields of the Tenant.
func (Tenant) Fields() []ent.Field {
	return []ent.Field{
		// ── Identity ─────────────────────────────────────────────────────────
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("name").
			NotEmpty().
			Comment("Display name of the organisation"),
		field.String("slug").
			NotEmpty().
			Unique().
			Comment("URL-safe identifier; used by all services to key tenant rows"),
		field.String("status").
			Default("active").
			Comment("active | inactive | suspended"),

		// ── Contact & Branding ────────────────────────────────────────────────
		field.String("contact_email").
			Optional().
			Nillable().
			Comment("Primary billing and alerts email for this organisation"),
		field.String("contact_phone").
			Optional().
			Nillable().
			Comment("Primary contact phone (E.164 format)"),
		field.String("logo_url").
			Optional().
			Nillable().
			Comment("URL to the organisation's logo"),
		field.String("website").
			Optional().
			Nillable().
			Comment("Organisation's public website"),
		field.String("country").
			Optional().
			Nillable().
			Default("KE").
			Comment("ISO 3166-1 alpha-2 country code"),
		field.String("timezone").
			Optional().
			Nillable().
			Default("Africa/Nairobi").
			Comment("IANA timezone for this tenant"),
		field.JSON("brand_colors", map[string]any{}).
			Optional().
			Comment("Brand palette: { primary, secondary, accent } — used by notification templates and UI theming"),


		// ── Organisation Profile ──────────────────────────────────────────────
		// Collected during multi-step registration to drive subscription recommendation.
		field.String("org_size").
			Optional().
			Nillable().
			Comment("Staff count band: 1-5 | 6-20 | 21-100 | 100+"),
		field.String("use_case").
			Optional().
			Nillable().
			Comment("Primary business use case (legacy single value). Use use_cases for multi-select."),
		field.JSON("use_cases", []string{}).
			Optional().
			Comment("Business use cases (multi-select): hospitality, retail, e_commerce, quick_service, food_delivery, grocery, manufacturing, warehousing, logistics, weighbridge, services, pharmacy, other"),

		// ── Subscription Tier Cache ────────────────────────────────────────────
		// Denormalized from subscription-api for fast JWT enrichment and auth checks.
		// Updated via background sync whenever the subscription changes.
		field.String("subscription_plan").
			Optional().
			Nillable().
			Comment("Active plan code: STARTER | GROWTH | PROFESSIONAL (denormalized from subscription-api)"),
		field.String("subscription_status").
			Optional().
			Nillable().
			Comment("ACTIVE | TRIAL | EXPIRED | CANCELLED (denormalized from subscription-api)"),
		field.Time("subscription_expires_at").
			Optional().
			Nillable().
			Comment("UTC expiry of the current subscription period"),
		field.String("subscription_id").
			Optional().
			Nillable().
			Comment("UUID of the TenantSubscription record in subscription-api; used for sync"),

		// ── Tier Limit Cache ───────────────────────────────────────────────────
		// JSON blob mirroring subscription-api tierLimitsJSON so auth-api can enforce
		// registration limits (max_admins, max_members) without a round-trip.
		field.JSON("tier_limits", map[string]any{}).
			Optional().
			Comment("Denormalized tier limits: max_members, max_admins, max_outlets, max_riders, max_orders_per_day, etc."),

		// ── Arbitrary Metadata ────────────────────────────────────────────────
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("Free-form key-value store for org-specific configuration"),

		// ── Timestamps ───────────────────────────────────────────────────────
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the Tenant.
func (Tenant) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("memberships", TenantMembership.Type),
	}
}

// Indexes of the Tenant.
func (Tenant) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("slug").Unique(),
		index.Fields("status"),
		index.Fields("subscription_plan"),
	}
}
