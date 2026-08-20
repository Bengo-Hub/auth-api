package handlers

import "testing"

func TestValidateTenantAppScopes(t *testing.T) {
	cases := []struct {
		name    string
		scopes  []string
		wantErr bool
	}{
		{"single treasury scope", []string{"treasury:read"}, false},
		{"single treasury read+write", []string{"treasury:read", "treasury:write"}, false},
		{"single notifications scope", []string{"notifications:read"}, false},
		{"empty scopes", []string{}, false},
		{"platform-only scope rejected", []string{"admin"}, true},
		{"s2s scope rejected", []string{"s2s:*"}, true},
		{"internal service key scope rejected", []string{InternalServiceKeyScope}, true},
		{"unrecognized prefix rejected", []string{"bogus:read"}, true},
		{"two different services rejected", []string{"treasury:read", "notifications:read"}, true},
		{"etims plus treasury rejected (different prefixes)", []string{"etims:read", "treasury:write"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTenantAppScopes(tc.scopes)
			if tc.wantErr && err == nil {
				t.Errorf("validateTenantAppScopes(%v) = nil, want an error", tc.scopes)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateTenantAppScopes(%v) = %v, want nil", tc.scopes, err)
			}
		})
	}
}
