package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// APIKey holds service API key data for service-to-service authentication.
// API keys provide an alternative to JWT tokens for automated operations,
// webhooks, cron jobs, and inter-service communication.
type APIKey struct {
	ent.Schema
}

// Fields defines the API key fields.
func (APIKey) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Key identification
		field.String("name").
			NotEmpty().
			Comment("Human-readable name for the API key"),
		field.String("key_hash").
			NotEmpty().
			Sensitive().
			Comment("SHA-256 hash of the API key (never store plain text)"),
		field.String("key_prefix").
			MaxLen(8).
			Comment("First 8 chars of key for identification (e.g., 'bng_live')"),

		// Ownership and scope
		field.UUID("tenant_id", uuid.UUID{}).
			Comment("Tenant this API key belongs to"),
		field.String("service").
			Optional().
			Comment("Service name if this is a service account key (e.g., 'ordering-service')"),
		field.UUID("created_by", uuid.UUID{}).
			Optional().
			Comment("User who created this API key"),

		// Permissions
		field.Strings("scopes").
			Optional().
			Comment("Allowed scopes for this API key"),
		field.Strings("allowed_ips").
			Optional().
			Comment("IP whitelist for additional security (empty = all IPs)"),

		// Status and lifecycle
		field.Enum("status").
			Values("active", "revoked", "expired").
			Default("active"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Expiration time (null = never expires)"),
		field.Time("last_used_at").
			Optional().
			Nillable().
			Comment("Last time this key was used"),
		field.String("last_used_ip").
			Optional().
			Comment("IP address of last usage"),

		// Audit
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
		field.Time("revoked_at").
			Optional().
			Nillable(),
		field.String("revoked_reason").
			Optional(),
	}
}

// Indexes defines the API key indexes.
func (APIKey) Indexes() []ent.Index {
	return []ent.Index{
		// Fast lookup by key hash (primary authentication lookup)
		index.Fields("key_hash").Unique(),
		// List keys by tenant
		index.Fields("tenant_id", "status"),
		// List keys by service
		index.Fields("service", "status"),
		// Find expired keys for cleanup
		index.Fields("status", "expires_at"),
	}
}
