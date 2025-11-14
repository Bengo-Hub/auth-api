package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// AuthorizationCode stores short-lived authorization codes for OIDC.
type AuthorizationCode struct {
	ent.Schema
}

// Fields of the AuthorizationCode.
func (AuthorizationCode) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("client_id").
			NotEmpty(),
		field.String("redirect_uri").
			NotEmpty(),
		field.String("scope").
			Default(""),
		field.String("code_hash").
			NotEmpty().
			Immutable(),
		field.String("code_challenge").
			Default(""),
		field.String("code_challenge_method").
			Default(""),
		field.String("nonce").
			Default(""),
		field.Time("expires_at"),
		field.Time("consumed_at").
			Optional(),
		field.JSON("metadata", map[string]any{}).
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Edges of the AuthorizationCode.
func (AuthorizationCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Field("user_id").
			Ref("authorization_codes").
			Unique().
			Required(),
	}
}
