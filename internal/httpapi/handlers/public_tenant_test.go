package handlers

import (
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/google/uuid"
)

// The unauthenticated tenant lookups never carry the tax PIN, the platform's internal records or
// anything named like a credential, and keep what frontends and services brand and contact with.
func TestPublicTenantResponseHidesPrivateData(t *testing.T) {
	pin := "P052287771R"
	tenant := &ent.Tenant{ID: uuid.New(), Name: "Urban Loft", Slug: "urban-loft", TaxPin: &pin, Metadata: map[string]any{
		"backup":           map[string]any{"key": "auth/x/backups/1.zip", "requested_by": "user-1"},
		"rejection_reason": "duplicate",
		"kra_pin":          "P0000",
		"payhero_api_key":  "x",
		"Webhook_Secret":   "y",
		"base_domain":      "theurbanloftcafe.com",
		"service_branding": map[string]any{"ordering": map[string]any{"name": "Urban Eats"}},
		"contact_phone":    "+254116010638",
		"isp_whatsapp":     "+254700000000",
	}}
	got := publicTenantResponseFrom(tenant)
	if got.TaxPin != nil {
		t.Fatal("the tax PIN is public")
	}
	for _, k := range []string{"backup", "rejection_reason", "kra_pin", "payhero_api_key", "Webhook_Secret"} {
		if _, ok := got.Metadata[k]; ok {
			t.Errorf("%s is public", k)
		}
	}
	for _, k := range []string{"base_domain", "service_branding", "contact_phone", "isp_whatsapp"} {
		if _, ok := got.Metadata[k]; !ok {
			t.Errorf("%s was dropped", k)
		}
	}
	if _, ok := tenant.Metadata["backup"]; !ok {
		t.Fatal("the stored metadata was changed")
	}
}
