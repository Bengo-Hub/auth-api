package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// OAuthClient holds OAuth client metadata.
type OAuthClient struct {
	ent.Schema
}

// Fields defines the client fields.
func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("client_id").
			NotEmpty().
			Unique(),
		field.String("client_secret").
			Sensitive().
			Optional(),
		field.String("name").
			NotEmpty(),
		field.Strings("redirect_uris").
			Optional(),
		field.Strings("allowed_scopes").
			Optional(),
		field.Bool("public").
			Default(false),
		field.String("tenant_id").
			Optional(),
		field.UUID("created_by", uuid.UUID{}).
			Optional(),
		field.JSON("metadata", map[string]any{}).
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}
