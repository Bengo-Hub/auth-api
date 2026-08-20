package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// IntegrationRequest tracks a request to enable a platform integration (starting with eTIMS)
// for either an onboarded tenant or an external, not-yet-onboarded company. Deliberately generic
// (request_type is extensible) rather than eTIMS-specific, since the same request/review/notify
// workflow will apply to future integrations the developer portal exposes.
type IntegrationRequest struct {
	ent.Schema
}

func (IntegrationRequest) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.String("request_type").
			Default("etims_integration").
			Comment("Which integration is being requested — extensible beyond eTIMS as the portal grows"),
		field.String("service").
			Optional().
			Comment("Single service this request is for (treasury, notifications, sso) — set for service_access_* requests from the generic developer-portal apply form; null for other request types like app_production_access"),
		field.UUID("tenant_id", uuid.UUID{}).
			Optional().
			Nillable().
			Comment("Set for an onboarded-tenant request; null for an external lead with no tenant yet"),
		field.String("requester_name").NotEmpty(),
		field.String("requester_email").NotEmpty(),
		field.String("requester_phone").Optional(),
		field.String("company_name").Optional(),
		field.String("kra_pin").Optional(),
		field.Enum("integration_mode").
			Values("self_serve", "assisted").
			Default("self_serve").
			Comment("self_serve = own developers, no integration fee; assisted = Codevertex team does the setup, one-time fee applies"),
		field.Text("notes").Optional().Comment("Requester-supplied context: device/branch count, timeline, etc."),
		field.Enum("source").
			Values("tenant_portal", "public_website", "go_live_gate").
			Default("tenant_portal"),
		field.Enum("status").
			Values("pending", "in_review", "approved", "rejected", "completed", "go_live_requested").
			Default("pending"),
		field.Text("admin_notes").Optional(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

func (IntegrationRequest) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("status"),
		index.Fields("request_type"),
		index.Fields("tenant_id"),
	}
}
