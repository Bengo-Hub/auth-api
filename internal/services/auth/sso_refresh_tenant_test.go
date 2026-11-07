package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/services/oidc"
)

// A person whose account was first made in one tenant (codevertex-demo) signs into another app's
// tenant (Hadia) through SSO. The SSO session keeps the tenant its token was issued for, so a
// refresh returns a Hadia token again, never one for the primary tenant (staging, 7 November 2026:
// the first refresh switched owners to codevertex-demo and Hadia refused every request). A session
// with no tenant keeps the old behaviour: the primary tenant.
func TestSSORefreshKeepsTheTokensTenant(t *testing.T) {
	s, client, tokens := newPhoneSignupTestService(t)
	ctx := context.Background()
	suffix := uuid.NewString()[:8]

	demo, err := client.Tenant.Create().SetName("Demo").SetSlug("demo-" + suffix).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hadia, err := client.Tenant.Create().SetName("Hadia").SetSlug("hadia-" + suffix).SetStatus("active").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.User.Create().SetEmail("owner-" + suffix + "@mail.test").SetStatus("active").
		SetPrimaryTenantID(demo.ID.String()).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range []uuid.UUID{demo.ID, hadia.ID} {
		if _, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(tn).SetRoles([]string{"customer"}).Save(ctx); err != nil {
			t.Fatal(err)
		}
	}

	o := oidc.New(client, tokens, s.cfg)
	refreshed := func(tenantID *uuid.UUID) uuid.UUID {
		sess, err := o.CreateSession(ctx, u.ID, tenantID, "hadia-ui", "127.0.0.1", "test", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Refresh(ctx, RefreshInput{RefreshToken: sess.RefreshToken, ClientID: "hadia-ui"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Tenant == nil {
			t.Fatal("refreshed token has no tenant")
		}
		return res.Tenant.ID
	}
	if got := refreshed(&hadia.ID); got != hadia.ID {
		t.Errorf("refresh of a Hadia SSO session gave tenant %s, want Hadia %s", got, hadia.ID)
	}
	if got := refreshed(nil); got != demo.ID {
		t.Errorf("refresh of a session with no tenant gave %s, want the primary tenant %s", got, demo.ID)
	}
}
