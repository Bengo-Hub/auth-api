package auth

import (
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
)

func TestTenantSubscriptionExempt(t *testing.T) {
	cases := []struct {
		name   string
		tenant *ent.Tenant
		want   bool
	}{
		{"no tenant", nil, false},
		// The platform tenant never pays for its own products: any member's token carries
		// sub_exempt, or MarketFlow's service gate answers 403 service_not_subscribed.
		{"platform tenant", &ent.Tenant{Slug: platformTenantSlug}, true},
		{"flagged tenant", &ent.Tenant{Slug: "acme", SubscriptionExempt: true}, true},
		// The demo tenant's password is public: it gets plan features, never an exemption.
		{"demo tenant", &ent.Tenant{Slug: "codevertex-demo"}, false},
		{"ordinary tenant", &ent.Tenant{Slug: "acme"}, false},
	}
	for _, c := range cases {
		if got := TenantSubscriptionExempt(c.tenant); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
