package auth

import (
	"context"
	"net/url"
	"strings"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/google/uuid"
)

// SafeOAuthReturnTo keeps a return_to only when it is somewhere the platform owns: a relative path, or
// an https URL on the issuer's host or the platform's own domain family. Anything else is dropped, so a
// crafted link can never turn the social callback into an open redirect.
func SafeOAuthReturnTo(raw, issuer string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\\\r\n") {
		return ""
	}
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") {
			return ""
		}
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if iu, iErr := url.Parse(issuer); iErr == nil && iu.Hostname() != "" && host == strings.ToLower(iu.Hostname()) {
		return raw
	}
	if host == "codevertexafrica.com" || strings.HasSuffix(host, ".codevertexafrica.com") {
		return raw
	}
	return ""
}

// userHomeTenant is the tenant a person signs in to when none was named: their primary tenant, else
// their first active membership. Same rule as password sign-in.
func (s *Service) userHomeTenant(ctx context.Context, u *ent.User) *ent.Tenant {
	if id, err := uuid.Parse(strings.TrimSpace(u.PrimaryTenantID)); err == nil {
		if t, tErr := s.entClient.Tenant.Get(ctx, id); tErr == nil && t.Status == "active" {
			// Only a tenant they actually belong to counts.
			if ok, _ := s.entClient.TenantMembership.Query().Where(tenantmembership.UserID(u.ID), tenantmembership.TenantID(t.ID)).Exist(ctx); ok {
				return t
			}
		}
	}
	m, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(u.ID), tenantmembership.HasTenantWith(tenant.StatusEQ("active"))).
		WithTenant().
		First(ctx)
	if err != nil || m.Edges.Tenant == nil {
		return nil
	}
	return m.Edges.Tenant
}
