package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// PasswordPolicy stores configurable password complexity/expiry rules.
// A row with tenant_id = NULL is the platform-wide default. New rules apply on
// the NEXT password change only — they never retroactively lock out users.
type PasswordPolicy struct {
	ent.Schema
}

// Fields of the PasswordPolicy.
func (PasswordPolicy) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Tenant identifier. NULL = platform-wide default policy."),
		field.Int("min_length").
			Default(8),
		field.Bool("require_upper").
			Default(true),
		field.Bool("require_lower").
			Default(true),
		field.Bool("require_digit").
			Default(true),
		field.Bool("require_symbol").
			Default(false),
		field.Int("expiry_days").
			Default(0).
			Comment("Days until a password expires; 0 = never."),
		field.Int("reuse_block_count").
			Default(0).
			Comment("Number of previous passwords that may not be reused; 0 = disabled."),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the PasswordPolicy.
func (PasswordPolicy) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id").Unique(),
	}
}
