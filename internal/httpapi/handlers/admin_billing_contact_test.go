package handlers

import "testing"

func TestPickBillingPhones(t *testing.T) {
	platformStaff := billingContactAdmin{Roles: []string{"superuser"}, ProfilePhone: "+254743793901"}
	manager := billingContactAdmin{Roles: []string{"manager"}, ProfilePhone: "+254700000001"}
	adminNoPhone := billingContactAdmin{Roles: []string{"admin"}}
	admin := billingContactAdmin{Roles: []string{"pos_admin"}, PrimaryPhone: "+254711000000", ProfilePhone: "+254722000000"}
	second := billingContactAdmin{Roles: []string{"admin"}, ProfilePhone: "+254733000000"}

	cases := []struct {
		name       string
		admins     []billingContactAdmin
		hq, tenant string
		want       []string
	}{
		{"one admin, then outlet, then tenant", []billingContactAdmin{platformStaff, manager, adminNoPhone, admin, second}, "0745112126", "254706832535",
			[]string{"tenant_admin:+254711000000", "main_outlet:0745112126", "tenant:254706832535"}},
		{"platform staff and managers never get the bill", []billingContactAdmin{platformStaff, manager, adminNoPhone}, "0745112126", "254706832535",
			[]string{"main_outlet:0745112126", "tenant:254706832535"}},
		{"the same number in two formats is listed once", nil, "0706832535", "254706832535", []string{"main_outlet:0706832535"}},
		{"nothing known", nil, "", "", nil},
	}
	for _, c := range cases {
		got := pickBillingPhones(c.admins, c.hq, c.tenant)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i, p := range got {
			if p.Source+":"+p.Phone != c.want[i] {
				t.Errorf("%s: [%d] = %s:%s, want %s", c.name, i, p.Source, p.Phone, c.want[i])
			}
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
