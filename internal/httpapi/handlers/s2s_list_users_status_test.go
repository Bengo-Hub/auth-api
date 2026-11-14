package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// GET /api/v1/s2s/{tenant}/users lists active members by default (erp's employee backfill relies
// on it) and, with ?status=all, suspended and invited members too, each with its status, so pos's
// staff bind check sees every admin who holds a role.
func TestS2SListTenantUsersStatusAll(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	shop := client.Tenant.Create().SetName("Shop").SetSlug("shop-" + sfx).SetStatus("active").SaveX(ctx)
	for _, s := range []string{"active", "suspended", memberStatusInvited} {
		u := client.User.Create().SetEmail(s + "-" + sfx + "@mail.test").SetStatus("active").SaveX(ctx)
		client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(shop.ID).SetRoles([]string{"admin"}).SetStatus(s).SaveX(ctx)
	}
	h := &AdminHandler{ent: client, logger: zap.NewNop()}

	list := func(query string) []map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/"+query, nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("tenant", shop.ID.String())
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		w := httptest.NewRecorder()
		h.S2SListTenantUsers(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var body []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	if got := list(""); len(got) != 1 || got[0]["status"] != nil {
		t.Fatalf("default: %v, want only the active member and no status field", got)
	}
	all := list("?status=all")
	seen := map[string]bool{}
	for _, m := range all {
		s, _ := m["status"].(string)
		seen[s] = true
	}
	if len(all) != 3 || !seen["active"] || !seen["suspended"] || !seen[memberStatusInvited] {
		t.Fatalf("status=all: %v, want all three members with their status", all)
	}
}
