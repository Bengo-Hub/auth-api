package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// PortalShortLink stores a short code that resolves to an equity portal JWT URL.
// A short code is an 8-char uppercase alphanumeric string e.g. "A3BX9K2Z".
// GET /p/:code on auth-api 302-redirects to /equity-holder/?token=<JWT>.
type PortalShortLink struct {
	ent.Schema
}

func (PortalShortLink) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),

		// 8-char uppercase alphanumeric short code, e.g. "A3BX9K2Z"
		field.String("code").
			NotEmpty().
			MaxLen(16).
			Unique().
			Comment("Short URL code included in /p/:code redirect URLs"),

		// treasury_holder_id from treasury-api (cross-service reference, no hard FK)
		field.UUID("holder_id", uuid.UUID{}).
			Comment("treasury-api equity_holder.id this link belongs to"),

		// Signed JWT token — same token that is appended to the full portal URL.
		// Stored so the redirect can be served without re-issuing a new JWT.
		field.Text("jwt_token").
			Comment("Signed equity portal JWT; appended to the redirect URL"),

		field.Time("expires_at").
			Comment("When the link (and its JWT) expires"),

		field.Int("clicks").
			Default(0).
			Comment("Total times the short link has been visited"),

		field.Time("created_at").
			Immutable().
			Default(time.Now),
	}
}

func (PortalShortLink) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code").Unique(),
		index.Fields("holder_id"),
		index.Fields("expires_at"),
	}
}
