package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// MFABackupCode stores single-use backup codes.
type MFABackupCode struct {
	ent.Schema
}

// Fields of the MFABackupCode.
func (MFABackupCode) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("code_hash").
			NotEmpty().
			Sensitive(),
		field.Time("used_at").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the MFABackupCode.
func (MFABackupCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("mfa_backup_codes").
			Field("user_id").
			Unique().
			Required(),
	}
}

