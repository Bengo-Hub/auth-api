package access

import (
	"reflect"
	"testing"
)

// The production role catalogue in miniature (2026-11-03): cashier is scoped to POS and its auth
// permissions add ordering; manager and staff are cross-service job roles; customer is platform
// scoped but not staff; driver belongs to logistics.
var catalogue = map[string]roleInfo{
	"admin":     {scope: "platform", services: set("inventory", "pos", "treasury", "ordering", "logistics")},
	"superuser": {scope: "platform", services: set("inventory", "pos", "treasury", "ordering", "logistics")},
	"cashier":   {scope: "pos", services: set("ordering")},
	"waiter":    {scope: "pos", services: set("ordering")},
	"barista":   {scope: "pos", services: set()},
	"manager":   {scope: "platform", services: set("inventory", "ordering")},
	"staff":     {scope: "platform", services: set("inventory", "logistics", "ordering", "treasury")},
	"customer":  {scope: "platform", services: set("ordering")},
	"driver":    {scope: "logistics", services: set("logistics")},
}

// The roles suggested for a service never include an admin role: taking one to reach a single
// service would hand over the whole organisation.
func TestRolesBackingLeavesOutAdminRoles(t *testing.T) {
	got := rolesBacking(catalogue, "inventory")
	if want := []string{"manager", "staff"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func set(s ...string) map[string]bool {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}
	return m
}

func TestEffectiveServices(t *testing.T) {
	plan := Entitlement{Tags: []string{"inventory", "ordering", "pos", "treasury"}}
	cases := []struct {
		name     string
		roles    []string
		assigned []string
		plan     Entitlement
		want     []string
	}{
		{"tenant admin gets the whole plan", []string{"admin"}, nil, plan, []string{"inventory", "ordering", "pos", "treasury"}},
		{"admin of an exempt tenant gets everything", []string{"superuser"}, nil, Entitlement{All: true}, []string{All}},
		{"unassigned cashier follows the role", []string{"cashier"}, nil, plan, []string{"ordering", "pos"}},
		{"unassigned barista: POS only", []string{"barista"}, nil, plan, []string{"pos"}},
		{"role outside the plan is dropped", []string{"driver"}, nil, plan, []string{}},
		{"unassigned manager keeps the plan until assigned", []string{"manager"}, nil, plan, []string{"inventory", "ordering", "pos", "treasury"}},
		{"unknown role keeps the plan until assigned", []string{"maskani_owner"}, nil, plan, []string{"inventory", "ordering", "pos", "treasury"}},
		{"assigned services within the plan", []string{"cashier"}, []string{"pos", "inventory", "logistics"}, plan, []string{"inventory", "pos"}},
		{"assigned manager may work in any planned service", []string{"manager"}, []string{"pos", "treasury"}, plan, []string{"pos", "treasury"}},
		{"assigned nothing means nothing", []string{"cashier"}, []string{}, plan, []string{}},
		{"customer is not a job role", []string{"customer"}, nil, plan, []string{"ordering"}},
		{"cashier plus inventory role", []string{"cashier", "staff"}, []string{"pos", "inventory"}, plan, []string{"inventory", "pos"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effective(tc.roles, tc.assigned, tc.plan, catalogue)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRoleBacksService(t *testing.T) {
	if roleBacks([]string{"cashier"}, catalogue, "inventory") {
		t.Fatal("a cashier-only member must not be backed for inventory")
	}
	if !roleBacks([]string{"cashier"}, catalogue, "pos") || !roleBacks([]string{"manager"}, catalogue, "inventory") ||
		!roleBacks([]string{"admin"}, catalogue, "treasury") {
		t.Fatal("scoped, job and admin roles must back their services")
	}
	if roleBacks([]string{"customer"}, catalogue, "inventory") {
		t.Fatal("a customer role must not back a staff service")
	}
}
