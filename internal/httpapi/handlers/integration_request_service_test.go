package handlers

import "testing"

// TestRequestableServicesScopePrefixes locks in a subtle, easy-to-regress correctness property:
// each requestable service's scopePrefix must match a prefix a real middleware actually checks
// (or be a documented placeholder), not just read plausibly. "treasury" in particular must map to
// "etims" -- see the doc comment on requestableServices for why a literal "treasury" prefix would
// silently issue a non-functional credential against the only real external consumer today.
func TestRequestableServicesScopePrefixes(t *testing.T) {
	want := map[string]string{
		"treasury":      "etims",
		"notifications": "notifications",
		"sso":           "sso",
	}
	if len(requestableServices) != len(want) {
		t.Fatalf("requestableServices has %d entries, want %d", len(requestableServices), len(want))
	}
	for service, wantPrefix := range want {
		meta, ok := requestableServices[service]
		if !ok {
			t.Errorf("requestableServices missing entry for %q", service)
			continue
		}
		if meta.scopePrefix != wantPrefix {
			t.Errorf("requestableServices[%q].scopePrefix = %q, want %q", service, meta.scopePrefix, wantPrefix)
		}
		if meta.docsResourceKey == "" {
			t.Errorf("requestableServices[%q].docsResourceKey is empty", service)
		}
	}
}

func TestIsAutoProvisionable(t *testing.T) {
	cases := []struct {
		requestType string
		want        bool
	}{
		{"etims_integration", true},
		{"docs_access_treasury-api", true},
		{"docs_access_auth-api", true},
		{"service_access_treasury", true},
		{"service_access_notifications", true},
		{"service_access_sso", true},
		{"app_production_access", false},
		{"something_else", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isAutoProvisionable(tc.requestType); got != tc.want {
			t.Errorf("isAutoProvisionable(%q) = %v, want %v", tc.requestType, got, tc.want)
		}
	}
}
