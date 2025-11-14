package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// ConsentSession records granted scopes/claims for clients.
type ConsentSession struct {
	ent.Schema
}

// Fields of the ConsentSession.
func (ConsentSession) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("client_id").
			NotEmpty(),
		field.String("granted_scopes").
			Default(""),
		field.JSON("granted_claims", map[string]any{}).
			Optional(),
		field.Time("expires_at").
			Optional(),
		field.Time("last_used_at").
			Optional(),
		field.JSON("metadata", map[string]any{}).
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
