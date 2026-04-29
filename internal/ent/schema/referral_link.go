package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// ReferralLink is an auth-service-level referral tracking record.
// A tenant generates a shareable link; when a new organisation signs up via the link
// a conversion event is emitted so treasury-api can update the Referral and issue rewards.
type ReferralLink struct {
	ent.Schema
}

func (ReferralLink) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("referrer_tenant_id", uuid.UUID{}).
			Comment("The tenant that owns this referral link"),

		field.String("referral_code").
			NotEmpty().
			MaxLen(32).
			Unique().
			Comment("Short unique code e.g. CVBK-XKQP included in the referral URL"),

		// program_id references a treasury-api ReferralProgram by UUID string.
		// No hard FK — cross-service reference resolved at runtime.
		field.String("program_id").
			Optional().
			MaxLen(64).
			Comment("treasury-api ReferralProgram.id (UUID string) this link belongs to"),

		field.Int("clicks").
			Default(0).
			Comment("Total visits to the referral URL"),

		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("nil = never expires"),

		field.Bool("is_active").
			Default(true),

		field.Time("created_at").
			Immutable().
			Default(time.Now),

		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

func (ReferralLink) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("referral_code").Unique(),
		index.Fields("referrer_tenant_id"),
		index.Fields("is_active"),
	}
}
