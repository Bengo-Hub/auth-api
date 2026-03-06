package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Permission holds the schema definition for a permission (resource:action code).
// Used for granular RBAC: add, read, read_own, change, change_own, delete, manage, manage_own per resource.
type Permission struct {
	ent.Schema
}

// Fields of the Permission.
func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.String("code").
			Unique().
			NotEmpty(),
		field.String("resource").
			NotEmpty(),
		field.String("action").
			NotEmpty(),
	}
}

// Indexes of the Permission.
func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("resource", "action").Unique(),
	}
}
