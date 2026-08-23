package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// LegalAcceptance records an entity's acceptance of a specific document version.
// Used to track consent for EPA, MSA, and DPA per tenant/user with an optional
// uploaded signature image (jpg/png) stored in object storage.
type LegalAcceptance struct {
	ent.Schema
}

func (LegalAcceptance) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		field.UUID("entity_id", uuid.UUID{}).
			Comment("UUID of the tenant or user who accepted"),

		field.Enum("entity_type").
			Values("tenant", "user").
			Comment("Whether entity_id refers to a tenant or a user"),

		field.Enum("doc_type").
			Values("EPA", "MSA", "DPA", "RESELLER_AGREEMENT"),

		field.String("doc_version").
			NotEmpty().
			MaxLen(32).
			Comment("Version of the document accepted"),

		field.Time("accepted_at"),

		field.String("ip_address").
			Optional().
			MaxLen(64),

		field.String("user_agent").
			Optional().
			MaxLen(512),

		field.String("signature_image_url").
			Optional().
			MaxLen(1024).
			Comment("Object storage URL of the uploaded signature image (jpg/png, max 2MB)"),

		field.Time("created_at").
			Immutable().
			Default(time.Now),
	}
}

func (LegalAcceptance) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("entity_id", "doc_type"),
		index.Fields("entity_id"),
	}
}
