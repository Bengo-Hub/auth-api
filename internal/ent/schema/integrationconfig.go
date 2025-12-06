package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// IntegrationConfig holds the schema definition for the IntegrationConfig entity.
type IntegrationConfig struct {
	ent.Schema
}

// Fields of the IntegrationConfig.
func (IntegrationConfig) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional().
			Nillable(), // Can be system-wide or tenant-specific
		field.String("service").
			NotEmpty().
			Comment("Service name e.g. google_oauth, slack_webhook"),
		field.String("config_data").
			NotEmpty().
			Sensitive().
			Comment("Encrypted JSON configuration"),
		field.String("key_id").
			NotEmpty().
			Comment("ID of the encryption key used"),
		field.Time("created_at").
			Default(time.Now),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Edges of the IntegrationConfig.
func (IntegrationConfig) Edges() []ent.Edge {
	return nil
}

// Indexes of the IntegrationConfig.
func (IntegrationConfig) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "service").
			Unique(),
	}
}
