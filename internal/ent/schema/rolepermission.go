package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RolePermission links a role name (e.g. "admin", "staff") to a permission.
// Role names match TenantMembership.Roles JSON array values.
type RolePermission struct {
	ent.Schema
}

// Fields of the RolePermission.
func (RolePermission) Fields() []ent.Field {
	return []ent.Field{
		field.String("role_name").
			NotEmpty(),
		field.Int("permission_id"),
	}
}

// Edges of the RolePermission.
func (RolePermission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("permission", Permission.Type).
			Required().
			Unique().
			Field("permission_id"),
	}
}

// Indexes of the RolePermission.
func (RolePermission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_name", "permission_id").Unique(),
		index.Fields("role_name"),
	}
}
