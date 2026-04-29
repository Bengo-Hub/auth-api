package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// EquityHolderApplication tracks an organisation's application to become an equity holder.
// Status flow: pending → kyc_pending → kyc_approved → epa_pending → approved | rejected
type EquityHolderApplication struct {
	ent.Schema
}

func (EquityHolderApplication) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("tenant_id", uuid.UUID{}).
			Comment("The applying organisation"),

		field.Enum("status").
			Values("pending", "kyc_pending", "kyc_approved", "epa_pending", "approved", "rejected").
			Default("pending"),

		field.String("kyc_reference").
			Optional().
			MaxLen(255).
			Comment("Smile Identity job_id returned when KYC is initiated"),

		field.Text("kyc_result").
			Optional().
			Comment("Raw JSON response from Smile Identity callback"),

		field.UUID("epa_acceptance_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("FK → legal_acceptance for the signed EPA"),

		field.UUID("treasury_holder_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("treasury-api equity_holder.id created after application is approved"),

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

func (EquityHolderApplication) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("status"),
		index.Fields("tenant_id", "status"),
	}
}
