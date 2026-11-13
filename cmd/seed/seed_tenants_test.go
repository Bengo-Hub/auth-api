package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bengobox/auth-api/internal/services/auth"
)

// The Hadia tenant seed turns MFA on for its three staff roles, in the shape sign-in reads.
func TestHadiaTenantSeedsTheStaffMFAPolicy(t *testing.T) {
	value := hadiaTenantSpec.defaultMetadata[auth.TenantMetadataMFAPolicy]
	// Read it back the way it is stored: as JSON.
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var stored any
	_ = json.Unmarshal(raw, &stored)
	p, ok := auth.ParseMFAPolicy(stored)
	if !ok || p.AllAccounts || strings.Join(p.RequiredRoles, ",") != "hadia_admin,hadia_finance,hadia_staff,hadia_support" {
		t.Fatalf("hadia mfa_policy = %+v (present %v)", p, ok)
	}
	for _, role := range hadiaStaffRoles {
		if hadiaRoles[role] == "" {
			t.Fatalf("%s is not in the seeded role catalogue", role)
		}
	}
	if _, enforced := hadiaTenantSpec.metadata[auth.TenantMetadataMFAPolicy]; enforced {
		t.Fatal("the policy must be a set-once default, or every deploy would undo a platform owner's edit")
	}
}

// The platform tenant is seeded with support@ as its support email, once: an edit survives a reseed.
func TestCodevertexSupportEmailSeed(t *testing.T) {
	fresh := seedTenantMetadata(nil, map[string]any{"is_platform_owner": true}, codevertexDefaultMetadata)
	support, _ := fresh["support"].(map[string]any)
	if support["email"] != "support@codevertexafrica.com" {
		t.Fatalf("seeded support = %v", fresh["support"])
	}
	edited := map[string]any{"support": map[string]any{"email": "help@codevertexafrica.com"}}
	again := seedTenantMetadata(edited, map[string]any{"is_platform_owner": true}, codevertexDefaultMetadata)
	if s, _ := again["support"].(map[string]any); s["email"] != "help@codevertexafrica.com" {
		t.Fatalf("reseed overwrote the edited support contact: %v", again["support"])
	}
}

// Enforced keys always win; a default fills only a gap, so an edited policy survives a reseed.
func TestSeedTenantMetadata(t *testing.T) {
	edited := map[string]any{"required_roles": []any{"hadia_admin"}}
	stored := map[string]any{"mfa_policy": edited, "phone_self_signup": false, "custom": "kept"}
	got := seedTenantMetadata(stored, hadiaTenantSpec.metadata, hadiaTenantSpec.defaultMetadata)
	if p, _ := auth.ParseMFAPolicy(got["mfa_policy"]); strings.Join(p.RequiredRoles, ",") != "hadia_admin" {
		t.Fatalf("reseed overwrote the edited policy: %v", got["mfa_policy"])
	}
	if got["phone_self_signup"] != true || got["custom"] != "kept" {
		t.Fatalf("merge: %v", got)
	}
	if stored["phone_self_signup"] != false {
		t.Fatal("the stored map was modified")
	}
	fresh := seedTenantMetadata(nil, hadiaTenantSpec.metadata, hadiaTenantSpec.defaultMetadata)
	if _, ok := auth.ParseMFAPolicy(fresh["mfa_policy"]); !ok {
		t.Fatal("a new Hadia tenant has no MFA policy")
	}
}
