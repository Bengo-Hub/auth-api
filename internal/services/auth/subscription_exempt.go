package auth

import "github.com/bengobox/auth-api/internal/ent"

// TenantSubscriptionExempt reports whether tokens scoped to t carry the sub_exempt claim, which
// lets every service skip subscription gating. True for a tenant the platform flagged exempt and
// always for the platform tenant itself, so any of its members (not only platform owners) can use
// the platform's own products: before this, a plain codevertex member, such as the Meta App Review
// account, got 403 service_not_subscribed on every MarketFlow call (2026-11-12). The demo tenant
// is never exempt by this rule.
func TenantSubscriptionExempt(t *ent.Tenant) bool {
	if t == nil {
		return false
	}
	return t.SubscriptionExempt || t.Slug == platformTenantSlug
}
