package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Role is a metadata-only descriptor for a role name. It is DECOUPLED from
// RolePermission: there is no edge/FK between the two. The join is purely by
// value (Role.role_code == RolePermission.role_name == TenantMembership.roles[]).
// This lets the admin UI present human-friendly role metadata (name, description,
// scope, is_system) without changing how token issuance resolves permissions.
type Role struct {
	ent.Schema
}

// Fields of the Role.
func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("role_code").
			Unique().
			NotEmpty().
			Comment("Stable identifier; equals RolePermission.role_name and TenantMembership.roles[] values."),
		field.String("name").
			NotEmpty().
			Comment("Human-readable display name."),
		field.String("description").
			Optional().
			Comment("Optional description of what the role grants."),
		field.Bool("is_system").
			Default(false).
			Comment("System roles cannot be edited or deleted via the admin API."),
		field.String("scope").
			Optional().
			Comment("Inferred scope grouping e.g. platform, erp, pos, logistics, ordering."),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the Role.
func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("is_system"),
	}
}
