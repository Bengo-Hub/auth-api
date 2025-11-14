package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// MFASettings stores per-user MFA policy and status.
type MFASettings struct {
	ent.Schema
}

// Fields of the MFASettings.
func (MFASettings) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("user_id", uuid.UUID{}).
			Unique(),
		field.String("primary_method").
			Default(""),
		field.Time("enforced_at").
			Optional(),
		field.String("recovery_channel").
			Default(""),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

