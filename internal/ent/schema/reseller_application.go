package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ResellerApplication tracks a business's application to become a certified
// reseller/partner of the Codevertex platform. Mirrors EquityHolderApplication's
// exact shape for a business/legal-entity applicant rather than an individual
// investor: KYB (business/legal-entity verification), not KYC, and a Reseller
// Agreement, not an Equity Participation Agreement.
// Status flow: pending → kyb_pending → kyb_approved → agreement_pending → approved | rejected
type ResellerApplication struct {
	ent.Schema
}

func (ResellerApplication) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("tenant_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Set when an EXISTING Codevertex tenant is applying to also become a certified reseller. Left null when a brand-new business (not yet a tenant) is applying; approval then creates a new Tenant and backfills this field with its id."),

		field.String("business_name").
			NotEmpty().
			Comment("Legal/trading name of the applying business"),

		field.String("business_registration_no").
			Optional().
			Nillable().
			Comment("Company registration number — KYB reference document"),

		field.String("tax_pin").
			Optional().
			Nillable().
			Comment("KRA PIN / tax registration number"),

		field.String("contact_email").
			NotEmpty().
			Comment("Primary contact email for the applying business"),

		field.String("contact_phone").
			Optional().
			Nillable().
			Comment("Primary contact phone (E.164 format)"),

		field.String("country").
			Optional().
			Nillable().
			Default("KE").
			Comment("ISO 3166-1 alpha-2 country code"),

		field.Enum("requested_tier").
			Values("registered", "certified", "premier").
			Default("registered").
			Comment("Certification tier requested: registered | certified | premier (Codevertex Certified Partner Program tiering ladder)"),

		field.Enum("status").
			Values("pending", "kyb_pending", "kyb_approved", "agreement_pending", "approved", "rejected").
			Default("pending"),

		field.String("kyb_reference").
			Optional().
			MaxLen(255).
			Comment("Internal case/ticket reference for the manual KYB (business/legal-entity) review. Phase 1 KYB is manual admin review only — no automated vendor (e.g. Smile Identity) is wired for resellers."),

		field.Text("kyb_result").
			Optional().
			Comment("Admin-entered notes/outcome of the manual KYB review"),

		field.UUID("agreement_acceptance_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("FK → legal_acceptance for the signed RESELLER_AGREEMENT"),

		field.Text("notes").
			Optional().
			Comment("Admin notes on the application"),

		field.Time("created_at").
			Immutable().
			Default(time.Now),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

func (ResellerApplication) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("status"),
		index.Fields("tenant_id", "status"),
	}
}
