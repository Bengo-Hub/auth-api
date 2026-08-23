package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bengobox/auth-api/internal/ent/resellerapplication"
	authmiddleware "github.com/bengobox/auth-api/internal/httpapi/middleware"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func reqWithTenantClaims(method, url string, tenantID string) *http.Request {
	r := httptest.NewRequest(method, url, nil)
	if tenantID == "" {
		return r
	}
	return r.WithContext(authmiddleware.ContextWithClaims(r.Context(), &token.Claims{TenantID: tenantID}))
}

func TestResellerPortalHandler_RejectsUnauthenticated(t *testing.T) {
	h := &ResellerPortalHandler{}
	cases := []struct {
		name string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"GetOwnStatus", h.GetOwnStatus},
		{"GetOwnClients", h.GetOwnClients},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.fn(rec, reqWithTenantClaims(http.MethodGet, "/", ""))
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d (no claims must be rejected before touching ent)", rec.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestResellerPortalHandler_RejectsInvalidTenantID(t *testing.T) {
	h := &ResellerPortalHandler{}
	rec := httptest.NewRecorder()
	h.GetOwnStatus(rec, reqWithTenantClaims(http.MethodGet, "/", "not-a-uuid"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (non-UUID tenant claim must be rejected before touching ent)", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetOwnStatus_ForbiddenWhenNotReseller(t *testing.T) {
	client := newResellerTestClient(t)
	h := NewResellerPortalHandler(client, zap.NewNop())
	ctx := context.Background()

	tenant, err := client.Tenant.Create().
		SetName("Not A Reseller Ltd").
		SetSlug("not-a-reseller-" + uuid.New().String()[:8]).
		Save(ctx)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	rec := httptest.NewRecorder()
	h.GetOwnStatus(rec, reqWithTenantClaims(http.MethodGet, "/", tenant.ID.String()))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestGetOwnStatus_ReturnsTierFromApprovedApplication(t *testing.T) {
	client := newResellerTestClient(t)
	h := NewResellerPortalHandler(client, zap.NewNop())
	ctx := context.Background()

	tenant, err := client.Tenant.Create().
		SetName("Acme Resellers Ltd").
		SetSlug("acme-resellers-" + uuid.New().String()[:8]).
		SetIsReseller(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create reseller tenant: %v", err)
	}

	app, err := client.ResellerApplication.Create().
		SetBusinessName("Acme Resellers Ltd").
		SetContactEmail("partner@acme.example").
		SetRequestedTier(resellerapplication.RequestedTierCertified).
		SetStatus(resellerapplication.StatusApproved).
		SetTenantID(tenant.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("create approved application: %v", err)
	}

	rec := httptest.NewRecorder()
	h.GetOwnStatus(rec, reqWithTenantClaims(http.MethodGet, "/", tenant.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	for _, want := range []string{`"is_reseller":true`, `"requested_tier":"certified"`, `"business_name":"Acme Resellers Ltd"`, app.ID.String()} {
		if !strings.Contains(body, want) {
			t.Errorf("response body missing %q; body=%s", want, body)
		}
	}
}

func TestGetOwnClients_ListsOnlyManagedTenants(t *testing.T) {
	client := newResellerTestClient(t)
	h := NewResellerPortalHandler(client, zap.NewNop())
	ctx := context.Background()

	reseller, err := client.Tenant.Create().
		SetName("Acme Resellers Ltd").
		SetSlug("acme-resellers-" + uuid.New().String()[:8]).
		SetIsReseller(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create reseller tenant: %v", err)
	}
	otherReseller, err := client.Tenant.Create().
		SetName("Other Reseller Ltd").
		SetSlug("other-reseller-" + uuid.New().String()[:8]).
		SetIsReseller(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create other reseller tenant: %v", err)
	}

	managedClient, err := client.Tenant.Create().
		SetName("Managed Client Co").
		SetSlug("managed-client-" + uuid.New().String()[:8]).
		SetManagedByResellerTenantID(reseller.ID).
		Save(ctx)
	if err != nil {
		t.Fatalf("create managed client tenant: %v", err)
	}
	if _, err := client.Tenant.Create().
		SetName("Unmanaged Co").
		SetSlug("unmanaged-" + uuid.New().String()[:8]).
		Save(ctx); err != nil {
		t.Fatalf("create unmanaged tenant: %v", err)
	}
	if _, err := client.Tenant.Create().
		SetName("Someone Else's Client Co").
		SetSlug("someone-elses-client-" + uuid.New().String()[:8]).
		SetManagedByResellerTenantID(otherReseller.ID).
		Save(ctx); err != nil {
		t.Fatalf("create other reseller's client tenant: %v", err)
	}

	rec := httptest.NewRecorder()
	h.GetOwnClients(rec, reqWithTenantClaims(http.MethodGet, "/", reseller.ID.String()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, managedClient.ID.String()) {
		t.Errorf("expected managed client %s in response; body=%s", managedClient.ID.String(), body)
	}
	if strings.Contains(body, "Unmanaged Co") {
		t.Errorf("an unmanaged tenant leaked into another reseller's client list; body=%s", body)
	}
	if strings.Contains(body, "Someone Else's Client Co") {
		t.Errorf("another reseller's client leaked into this reseller's client list; body=%s", body)
	}
}
