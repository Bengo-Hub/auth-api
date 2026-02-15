package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// OutboxEvent stores events for reliable publishing via the transactional outbox pattern.
type OutboxEvent struct {
	ent.Schema
}

// Fields of the OutboxEvent.
func (OutboxEvent) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant context for the event"),
		field.String("aggregate_type").
			NotEmpty().
			Comment("Entity type (user, tenant, session, etc.)"),
		field.UUID("aggregate_id", uuid.UUID{}).
			Comment("Entity ID"),
		field.String("event_type").
			NotEmpty().
			Comment("Event name (created, updated, login, etc.)"),
		field.JSON("payload", []byte{}).
			Comment("Full event JSON payload"),
		field.Enum("status").
			Values("PENDING", "PUBLISHED", "FAILED").
			Default("PENDING"),
		field.Int("attempts").
			Default(0),
		field.Time("last_attempt_at").
			Optional().
			Nillable(),
		field.Time("published_at").
			Optional().
			Nillable(),
		field.String("error_message").
			Optional().
			Nillable(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
	}
}

// Indexes of the OutboxEvent.
func (OutboxEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("aggregate_type", "aggregate_id"),
		index.Fields("event_type"),
		index.Fields("status"),
		index.Fields("created_at"),
	}
}
