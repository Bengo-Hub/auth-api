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
			Default(uuid.New).
			Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Tenant identifier. NULL = platform-level integration."),
		field.String("name").
			NotEmpty().
			Comment("Unique integration name e.g. google_oauth, paystack, slack"),
		field.String("display_name").
			NotEmpty().
			Comment("Human-readable name"),
		field.String("description").
			Optional().
			Comment("Description of the integration"),
		field.String("base_url").
			Optional().
			Comment("Base URL for the external service"),
		field.Text("encrypted_credentials").
			NotEmpty().
			Sensitive().
			Comment("AES-256-GCM encrypted JSON credentials"),
		field.JSON("endpoints_json", map[string]string{}).
			Optional().
			Comment("Mapping of action names to endpoint paths"),
		field.Bool("is_active").
			Default(true).
			Comment("Whether this integration is currently active"),
		field.String("status").
			Default("active").
			Comment("Status: active, inactive, error, pending"),
		field.String("environment").
			Default("production").
			Comment("Environment: production, sandbox, test"),
		field.String("key_id").
			Optional().
			Comment("ID of the encryption key used (if using multiple keys)"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
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
		index.Fields("tenant_id", "name").
			Unique(),
		index.Fields("name"),
		index.Fields("is_active"),
	}
}
