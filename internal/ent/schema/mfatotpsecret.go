package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// MFATOTPSecret stores TOTP configuration for a user.
type MFATOTPSecret struct {
	ent.Schema
}

// Fields of the MFATOTPSecret.
func (MFATOTPSecret) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("secret").
			Sensitive().
			NotEmpty(),
		field.Int("digits").
			Default(6),
		field.Int("period").
			Default(30),
		field.Time("enabled_at").
			Optional(),
		field.Time("last_used_at").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the MFATOTPSecret.
func (MFATOTPSecret) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("mfa_totp").
			Field("user_id").
			Unique().
			Required(),
	}
}

