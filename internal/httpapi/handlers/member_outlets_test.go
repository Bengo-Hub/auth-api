package handlers

import (
	"errors"
	"reflect"
	"testing"
)

func TestResolveMemberOutlets(t *testing.T) {
	list := func(ids ...string) *[]string { return &ids }

	cases := []struct {
		name      string
		roles     []string
		current   []string
		requested *[]string
		limit     []string
		home      string
		changed   bool
		err       error
	}{
		{name: "manager gets several", roles: []string{"manager"}, requested: list("A", "b", "a"), limit: []string{"a", "b"}, changed: true},
		{name: "accountant gets several", roles: []string{"accountant"}, requested: list("a", "b"), limit: []string{"a", "b"}, changed: true},
		{name: "warehouse manager gets several", roles: []string{"warehouse_manager"}, requested: list("a", "b"), limit: []string{"a", "b"}, changed: true},
		{name: "manager cleared to tenant-wide", roles: []string{"manager"}, current: []string{"a"}, requested: list(), limit: []string{}, changed: true},
		{name: "manager untouched", roles: []string{"manager"}, current: []string{"a"}, limit: []string{"a"}},
		{name: "cashier refused several", roles: []string{"cashier"}, requested: list("a", "b"), err: errOutletsSingleRole},
		{name: "floor supervisor refused several", roles: []string{"floor_supervisor"}, requested: list("a", "b"), err: errOutletsSingleRole},
		{name: "cashier one outlet is home", roles: []string{"cashier"}, requested: list("a"), home: "a", changed: true},
		{name: "widest role wins", roles: []string{"cashier", "manager"}, requested: list("a", "b"), limit: []string{"a", "b"}, changed: true},
		{name: "losing the role keeps the first", roles: []string{"cashier"}, current: []string{"a", "b"}, home: "a", changed: true},
		{name: "admin refused a list", roles: []string{"admin"}, requested: list("a"), err: errOutletsAdminTenantWide},
		{name: "becoming admin clears the list", roles: []string{"admin"}, current: []string{"a"}, changed: true},
		{name: "cashier untouched", roles: []string{"cashier"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limit, home, changed, err := resolveMemberOutlets(c.roles, c.current, c.requested)
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v", err, c.err)
			}
			if !reflect.DeepEqual(limit, c.limit) || home != c.home || changed != c.changed {
				t.Fatalf("got limit=%v home=%q changed=%v, want limit=%v home=%q changed=%v", limit, home, changed, c.limit, c.home, c.changed)
			}
		})
	}
}
