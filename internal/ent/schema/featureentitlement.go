package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// FeatureEntitlement stores feature gating for tenants.
type FeatureEntitlement struct {
	ent.Schema
}

func (FeatureEntitlement) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}),
		field.String("feature_code").
			NotEmpty(),
		field.JSON("limit_json", map[string]any{}).
			Optional(),
		field.String("plan_source").
			Default(""),
		field.Time("synced_at").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

