package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// UserPhone stores every mobile number a user has registered against their
// account, mirroring Zoho's "My Mobile Numbers" — same verified/primary
// shape as UserEmail. Distinct from any rider-KYC phone field owned by
// logistics-service; this is the SSO-level contact number only.
type UserPhone struct {
	ent.Schema
}

func (UserPhone) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.String("phone").
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

func (UserPhone) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("phones").
			Field("user_id").
			Required().
			Unique(),
	}
}

func (UserPhone) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("phone").
			Unique(),
		index.Fields("user_id"),
	}
}
