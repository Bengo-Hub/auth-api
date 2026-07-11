package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("email").
			NotEmpty().
			Unique(),
		field.String("password_hash").
			Optional().
			Sensitive(),
		field.String("status").
			Default("active"),
		field.Time("created_at").
			Default(time.Now).
			Immutable(),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now),
		field.String("primary_tenant_id").
			Optional().
			MaxLen(128),
		field.JSON("profile", map[string]any{}).
			Optional(),
		field.Time("last_login_at").
			Optional(),
		field.Bool("terms_accepted").
			Default(false),
		field.Time("terms_accepted_at").
			Optional().
			Nillable(),
		// email_verified is the durable per-user verification flag. Set true at the end
		// of self-signup Register (email already OTP-proven) and when a Google-verified
		// identity is linked; false for admin/direct-add accounts until they verify.
		// Surfaced in JWT claims, /me, and auth.user.* events so downstream services
		// (notifications gating, shared-ui verify banner) can act on it.
		field.Bool("email_verified").
			Default(false),
		field.Time("email_verified_at").
			Optional().
			Nillable(),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("memberships", TenantMembership.Type),
		edge.To("sessions", Session.Type),
		edge.To("password_reset_tokens", PasswordResetToken.Type),
		edge.To("identities", UserIdentity.Type),
		edge.To("authorization_codes", AuthorizationCode.Type),
		edge.To("mfa_totp", MFATOTPSecret.Type),
		edge.To("mfa_backup_codes", MFABackupCode.Type),
		edge.To("webauthn_credentials", WebAuthnCredential.Type),
	}
}
