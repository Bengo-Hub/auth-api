package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// UserEmail stores every email address a user has registered against their
// account (beyond the single primary User.email column), mirroring Zoho's
// "My Email Addresses" — each can be independently verified and one is
// flagged primary. "Only one primary per user" is enforced in the handler
// (transactionally unset the others), not a DB constraint — see
// UserPhone for the identical pattern.
type UserEmail struct {
	ent.Schema
}

func (UserEmail) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("email").
			NotEmpty(),
		field.Bool("is_verified").
			Default(false),
		field.Time("verified_at").
			Optional().
			Nillable(),
		field.Bool("is_primary").
			Default(false),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

func (UserEmail) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("emails").
			Field("user_id").
			Required().
			Unique(),
	}
}

func (UserEmail) Indexes() []ent.Index {
	return []ent.Index{
		// An email address is a login handle — must be globally unique,
		// same as the primary User.email column.
		index.Fields("email").
			Unique(),
		index.Fields("user_id"),
	}
}
