package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TenantMembership represents membership relationships.
type TenantMembership struct {
	ent.Schema
}

// Fields of the TenantMembership.
func (TenantMembership) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		field.UUID("tenant_id", uuid.UUID{}),
		field.JSON("roles", []string{}).
			Optional(),
		field.UUID("outlet_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Home outlet for this user in this tenant; nil = unassigned / tenant-wide"),
		field.String("status").
			Default("active"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the TenantMembership.
func (TenantMembership) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("memberships").
			Field("user_id").
			Unique().
			Required(),
		edge.From("tenant", Tenant.Type).
			Ref("memberships").
			Field("tenant_id").
			Unique().
			Required(),
	}
}

// Indexes of the TenantMembership.
func (TenantMembership) Indexes() []ent.Index {
	return []ent.Index{
		// Unique constraint: a user can only have one membership per tenant
		index.Fields("user_id", "tenant_id").
			Unique(),
	}
}
