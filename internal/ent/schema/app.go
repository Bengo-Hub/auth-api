package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// App represents a platform or tenant application that can make S2S calls.
// Unlike developer APIKey (for user-facing integrations), an App is a first-class
// identity for a service or integration — similar to a GitHub App.
type App struct {
	ent.Schema
}

// Fields defines the App entity fields.
func (App) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// Identity
		field.String("name").
			NotEmpty().
			Comment("Human-readable app name, e.g. 'Codevertex Platform Services'"),
		field.String("description").
			Optional().
			Comment("Optional description of what this app does"),
		field.Enum("app_type").
			Values("platform", "tenant").
			Default("tenant").
			Comment("platform = cross-tenant S2S; tenant = scoped to a single tenant"),
		field.Enum("environment").
			Values("sandbox", "production").
			Default("sandbox").
			Comment("sandbox = test credentials, no production API access; production = live, requires promotion"),

		// Ownership
		field.UUID("tenant_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Owning tenant (null for platform-level apps)"),
		field.UUID("created_by", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("User who created this app"),

		// Token identity (GitHub-style: client_id is public; token is the secret)
		field.String("client_id").
			NotEmpty().
			Unique().
			Comment("Public app identifier shown in UI, e.g. 'app_abc123'"),
		field.String("key_hash").
			NotEmpty().
			Sensitive().
			Comment("SHA-256 hash of the full app token — never store plain text"),
		field.String("key_prefix").
			MaxLen(20).
			Comment("First 16 chars of token for identification in lists, e.g. 'bng_app_AbCdEf12'"),
		// Consumer secret for the OAuth2 client_credentials grant. client_id is the consumer
		// key; this secret is shown once and only its SHA-256 hash is kept. Null means the app
		// predates the grant and has not generated a secret yet.
		field.String("client_secret_hash").
			Optional().
			Nillable().
			Sensitive().
			Comment("SHA-256 hash of the consumer secret (client_credentials grant); null = none issued"),
		field.Time("client_secret_rotated_at").
			Optional().
			Nillable().
			Comment("When the consumer secret was last issued; tokens minted before it are refused"),

		// Permissions
		field.Strings("scopes").
			Optional().
			Comment("Allowed scopes, e.g. ['s2s:*', 'treasury:read']"),
		field.Strings("allowed_ips").
			Optional().
			Comment("IP whitelist (empty = all IPs allowed)"),

		// Lifecycle. suspended is a reversible, temporary pause (Resume clears it back to
		// active) distinct from revoked (permanent, audit-logged, never reversible).
		field.Enum("status").
			Values("active", "revoked", "expired", "suspended").
			Default("active"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("Token expiry (null = never expires)"),
		field.Time("last_used_at").
			Optional().
			Nillable(),
		field.String("last_used_ip").
			Optional(),

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

		// General per-app details that do not earn their own column. Today it holds the
		// rotation grace entries: previous_client_secret and previous_key, each
		// {hash, prefix, expires_at}, so the credential replaced by a rotation keeps working
		// until expires_at.
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("previous_client_secret, previous_key: {hash, prefix, expires_at} kept during a rotation grace period"),
	}
}

// Indexes defines App indexes.
func (App) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key_hash").Unique(),
		index.Fields("client_id").Unique(),
		index.Fields("tenant_id", "status"),
		index.Fields("app_type", "status"),
		index.Fields("status", "expires_at"),
		// Lets an X-API-Key that missed key_hash be found by the previous key it was rotated
		// from (metadata @> {"previous_key":{"hash":...}}). jsonb_path_ops keeps the index
		// small and serves exactly that containment query.
		index.Fields("metadata").
			Annotations(
				entsql.IndexTypes(map[string]string{dialect.Postgres: "GIN"}),
				entsql.OpClass("jsonb_path_ops"),
			),
	}
}
