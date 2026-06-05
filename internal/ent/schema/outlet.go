package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Outlet represents a physical or logical branch, store, warehouse, or point-of-sale
// location within a tenant organisation. Each outlet can be configured with a
// specific use case (hospitality, retail, pharmacy, etc.) which drives what
// modules are visible to staff logged into that outlet.
type Outlet struct {
	ent.Schema
}

// Fields of the Outlet.
func (Outlet) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// ── Ownership ────────────────────────────────────────────────────────
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Owning tenant — all downstream services scope queries to this"),

		// ── Identity ─────────────────────────────────────────────────────────
		field.String("code").
			NotEmpty().
			Comment("Short identifier unique per tenant, e.g. 'MAIN', 'NRB-01', 'AIRPORT'"),
		field.String("name").
			NotEmpty().
			Comment("Human-readable display name shown on PIN login and header"),

		// ── Use Case ─────────────────────────────────────────────────────────
		// Controls which modules are visible in pos-ui and inventory-ui for this outlet.
		field.String("use_case").
			Default("hospitality").
			Comment("Primary use case: hospitality | quick_service | retail | pharmacy | services | warehouse | logistics | commercial_weighing | axle_load_enforcement | manufacturing"),

		// ── Location ─────────────────────────────────────────────────────────
		field.String("address").
			Optional().
			Nillable().
			Comment("Physical address of this outlet/branch"),
		field.String("timezone").
			Optional().
			Nillable().
			Default("Africa/Nairobi").
			Comment("IANA timezone — used for shift/day boundaries"),

		// ── Flags ────────────────────────────────────────────────────────────
		// HQ outlets bypass per-outlet data scoping: users at HQ can see all
		// outlets' data. Mirrors TruLoad's is_hq_user pattern.
		field.Bool("is_hq").
			Default(false).
			Comment("HQ outlets can see data across all sibling outlets (no scoping filter)"),

		// ── Status ───────────────────────────────────────────────────────────
		field.String("status").
			Default("active").
			Comment("active | closed | archived"),

		// ── PIN Login Config ─────────────────────────────────────────────────
		// Admin-configurable message displayed on the PIN login screen for this outlet.
		field.String("pin_login_message").
			Optional().
			Nillable().
			Comment("Message shown on PIN login page, e.g. 'Welcome to Airport Branch — Shift starts 8AM'"),

		// ── Metadata ─────────────────────────────────────────────────────────
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("Free-form per-outlet configuration (custom_modules override, screensaver_url, etc.)"),

		// ── Timestamps ───────────────────────────────────────────────────────
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the Outlet.
func (Outlet) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("tenant", Tenant.Type).
			Ref("outlets").
			Field("tenant_id").
			Required().
			Unique(),
	}
}

// Indexes of the Outlet.
func (Outlet) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "code").Unique(),
		index.Fields("tenant_id", "status"),
		index.Fields("tenant_id", "is_hq"),
	}
}
