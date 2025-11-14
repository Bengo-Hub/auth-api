package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// UsageMetric aggregates per-day usage by tenant.
type UsageMetric struct {
	ent.Schema
}

func (UsageMetric) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}),
		field.Time("metric_date"),
		field.Int("active_users").
			Default(0),
		field.Int("auth_transactions").
			Default(0),
		field.Int("mfa_prompts").
			Default(0),
		field.Int("machine_tokens").
			Default(0),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

