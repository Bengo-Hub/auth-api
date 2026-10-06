package handlers

import "testing"

func TestPickBillingPhone(t *testing.T) {
	platformStaff := billingContactAdmin{Roles: []string{"superuser"}, ProfilePhone: "+254743793901"}
	manager := billingContactAdmin{Roles: []string{"manager"}, ProfilePhone: "+254700000001"}
	adminNoPhone := billingContactAdmin{Roles: []string{"admin"}}
	admin := billingContactAdmin{Roles: []string{"pos_admin"}, PrimaryPhone: "+254711000000", ProfilePhone: "+254722000000"}

	cases := []struct {
		name                string
		admins              []billingContactAdmin
		hq, tenant          string
		wantPhone, wantFrom string
	}{
		{"admin primary phone wins", []billingContactAdmin{platformStaff, manager, adminNoPhone, admin}, "0745112126", "254706832535", "+254711000000", "tenant_admin"},
		{"platform staff and managers never get the bill", []billingContactAdmin{platformStaff, manager, adminNoPhone}, "0745112126", "254706832535", "0745112126", "main_outlet"},
		{"tenant phone last", nil, "", "254706832535", "254706832535", "tenant"},
		{"nothing known", nil, "", "", "", ""},
	}
	for _, c := range cases {
		phone, from := pickBillingPhone(c.admins, c.hq, c.tenant)
		if phone != c.wantPhone || from != c.wantFrom {
			t.Errorf("%s: got %q/%q, want %q/%q", c.name, phone, from, c.wantPhone, c.wantFrom)
		}
	}
}

func TestOutletContactPhone(t *testing.T) {
	meta := map[string]any{"contact_phones": []any{map[string]any{"label": "Branch", "value": "0745112126"}}}
	if got := outletContactPhone(meta); got != "0745112126" {
		t.Fatalf("got %q", got)
	}
	if got := outletContactPhone(map[string]any{"phone": " 0700 "}); got != "0700" {
		t.Fatalf("plain phone: got %q", got)
	}
}
