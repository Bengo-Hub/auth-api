package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// TenantDomain is a tenant's own hostname (alphachinamarket.co.ke) connected to one platform
// service (the ordering storefront, TruLoad, the ERP, ...). Added from the SSO client area or by
// a platform admin; the domains reconciler (internal/services/domains) then creates the DNS
// record when the zone is in our Cloudflare account, the Kubernetes Ingress with a cert-manager
// certificate, and the service's OAuth redirect URIs, and marks it active once the certificate
// is ready.
type TenantDomain struct {
	ent.Schema
}

// Fields of the TenantDomain.
func (TenantDomain) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(uuid.New).Immutable(),
		field.UUID("tenant_id", uuid.UUID{}).Comment("Owning tenant"),
		field.String("service").NotEmpty().
			Comment("Platform service the domain serves, a key of the domains service catalogue (ordering, truload, erp, ...)"),
		// A hostname can only ever point at one tenant's service, so it is unique platform wide.
		field.String("hostname").NotEmpty().Unique().
			Comment("Lower-case hostname without scheme or port, e.g. shop.example.co.ke"),
		field.String("status").Default("pending_dns").
			Comment("pending_dns | issuing | active | failed | removing"),
		field.String("dns_mode").Default("external").
			Comment("cloudflare: we manage the record in our account; external: the tenant adds it"),
		field.String("cf_zone_id").Optional().Comment("Cloudflare zone that holds the record (dns_mode=cloudflare)"),
		field.String("cf_record_id").Optional().Comment("DNS record we created, removed with the domain"),
		field.String("last_error").Optional().Comment("Why the last reconcile step did not finish"),
		field.Time("last_checked_at").Optional().Nillable(),
		field.Time("activated_at").Optional().Nillable(),
		field.String("created_by").Optional().Comment("User id of whoever added it"),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
	}
}

// Indexes of the TenantDomain.
func (TenantDomain) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("status"),
	}
}
