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
	}
}
