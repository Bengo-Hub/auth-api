package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// WebAuthnCredential holds the schema definition for the WebAuthnCredential entity.
type WebAuthnCredential struct {
	ent.Schema
}

// Fields of the WebAuthnCredential.
func (WebAuthnCredential) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.UUID("user_id", uuid.UUID{}),
		// credential_id is the raw bytes ID returned by the authenticator during registration.
		field.Bytes("credential_id").
			Unique(),
		// public_key is the COSE-encoded public key.
		field.Bytes("public_key"),
		// aaguid is the authenticator attestation GUID identifying the authenticator model.
		field.String("aaguid").
			Optional(),
		// sign_count is used to detect cloned authenticators (replay protection).
		field.Uint32("sign_count").
			Default(0),
		// transports stores the authenticator transport hints (e.g., ["internal", "hybrid"]).
		field.JSON("transports", []string{}).
			Optional(),
		field.Bool("user_verified").
			Default(false),
		field.Bool("backup_eligible").
			Default(false),
		field.Bool("backup_state").
			Default(false),
		// friendly_name is an optional user-visible label (e.g. "iPhone Touch ID").
		field.String("friendly_name").
			Optional(),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("last_used_at").
			Optional().
			Nillable(),
	}
}

// Edges of the WebAuthnCredential.
func (WebAuthnCredential) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("webauthn_credentials").
			Field("user_id").
			Required().
			Unique(),
	}
}
