package auth

import (
	"context"
	"strings"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/services/usecase"
)

// TenantPathsKey is the OAuth client metadata key that turns per-tenant callbacks off. An app on
// its own domain serving one tenant (hadia-ui) sets it to false, so no other tenant's
// /{slug}/auth/callback is ever registered on it.
const TenantPathsKey = "tenant_paths"

// UsesTenantPaths reports whether a client takes /{slug}/auth/callback URIs at all.
// True unless its metadata sets tenant_paths to false.
func UsesTenantPaths(c *ent.OAuthClient) bool {
	if c == nil {
		return true
	}
	return metadataUsesTenantPaths(c.Metadata)
}

func metadataUsesTenantPaths(meta map[string]any) bool {
	v, ok := meta[TenantPathsKey].(bool)
	return !ok || v
}

// ServesUseCases reports whether the app takes /{slug}/auth/callback for a tenant with these use
// cases. Which app serves which use case comes from the one catalogue, usecase.Catalogue.
func ServesUseCases(clientID string, meta map[string]any, tenantUseCases []string) bool {
	if !metadataUsesTenantPaths(meta) {
		return false
	}
	return usecase.AppServes(clientID, tenantUseCases)
}

// ServesTenant reports whether the app takes the tenant's callbacks. The platform owner and demo
// tenants sign in to every app with per-tenant paths, whatever their own use cases: platform
// staff operate every service and the demo covers all of them.
func ServesTenant(clientID string, meta map[string]any, t *ent.Tenant) bool {
	if SignsInEverywhere(t) {
		return metadataUsesTenantPaths(meta)
	}
	return ServesUseCases(clientID, meta, TenantUseCases(t))
}

// SignsInEverywhere reports whether the tenant is the platform owner or a demo tenant.
func SignsInEverywhere(t *ent.Tenant) bool {
	if t == nil {
		return false
	}
	if t.IsDemo {
		return true
	}
	owner, _ := t.Metadata["is_platform_owner"].(bool)
	return owner
}

// TenantUseCases returns a tenant's use cases: use_cases, plus the legacy single use_case.
func TenantUseCases(t *ent.Tenant) []string {
	if t == nil {
		return nil
	}
	out := append([]string(nil), t.UseCases...)
	if t.UseCase != nil && *t.UseCase != "" {
		seen := false
		for _, u := range out {
			if u == *t.UseCase {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, *t.UseCase)
		}
	}
	return out
}

// AppendTenantRedirectURIs registers a tenant's /{slug}/auth/callback URIs on the OAuth clients
// that serve its use cases, and removes them from clients that do not. Called when a tenant is
// created (registration or admin API) so it can sign in at once without re-running the seed.
// Idempotent, so it also repairs a tenant whose use cases changed.
func AppendTenantRedirectURIs(ctx context.Context, entClient *ent.Client, t *ent.Tenant) error {
	return SyncTenantRedirectURIs(ctx, entClient, t, "")
}

// RenameTenantRedirectURIs moves a renamed tenant's redirect URIs from the old slug to the new one
// on every OAuth client: the new /{slug}/auth/callback URIs are added and the old slug's are
// removed, so a stale slug cannot keep receiving authorization codes. Idempotent.
func RenameTenantRedirectURIs(ctx context.Context, entClient *ent.Client, oldSlug string, t *ent.Tenant) error {
	return SyncTenantRedirectURIs(ctx, entClient, t, oldSlug)
}

// tenantRedirectURIs are the callback URIs one tenant slug owns on a client with production host.
func tenantRedirectURIs(prodHost, slug string) (prod, local string) {
	return "https://" + prodHost + "/" + slug + "/auth/callback", "http://localhost:3000/" + slug + "/auth/callback"
}

// SyncTenantRedirectURIs makes every OAuth client match the tenant: its callbacks present on the
// clients serving its use cases, absent elsewhere, and removeSlug's (when set) gone everywhere.
func SyncTenantRedirectURIs(ctx context.Context, entClient *ent.Client, t *ent.Tenant, removeSlug string) error {
	if t == nil {
		return nil
	}
	clients, err := entClient.OAuthClient.Query().All(ctx)
	if err != nil {
		return err
	}
	for _, c := range clients {
		serves := ServesTenant(c.ClientID, c.Metadata, t)
		if !serves && !UsesTenantPaths(c) {
			// A single-domain client never got tenant paths from us; leave its list alone.
			continue
		}
		uris, changed := nextRedirectURIs(c.RedirectUris, t.Slug, removeSlug, serves)
		if !changed {
			continue
		}
		if _, err := c.Update().SetRedirectUris(uris).Save(ctx); err != nil {
			return err
		}
	}
	return nil
}

// nextRedirectURIs returns a client's redirect URIs with slug's callbacks present (keep true) or
// absent (keep false), removeSlug's gone, and whether anything changed. Clients without a
// production callback host (no https .../auth/callback URI) are left alone.
func nextRedirectURIs(current []string, slug, removeSlug string, keep bool) ([]string, bool) {
	prodHost := inferProductionHost(current)
	if prodHost == "" {
		return current, false
	}
	changed := false
	uris := append([]string(nil), current...)
	drop := map[string]bool{}
	slugProd, slugLocal := tenantRedirectURIs(prodHost, slug)
	if keep {
		for _, u := range []string{slugProd, slugLocal} {
			if !containsURI(uris, u) {
				uris = append(uris, u)
				changed = true
			}
		}
	} else {
		drop[strings.ToLower(slugProd)] = true
		drop[strings.ToLower(slugLocal)] = true
	}
	if removeSlug != "" && !strings.EqualFold(removeSlug, slug) {
		oldProd, oldLocal := tenantRedirectURIs(prodHost, removeSlug)
		drop[strings.ToLower(oldProd)] = true
		drop[strings.ToLower(oldLocal)] = true
	}
	if len(drop) > 0 {
		kept := uris[:0]
		for _, u := range uris {
			if drop[strings.ToLower(strings.TrimSpace(u))] {
				changed = true
				continue
			}
			kept = append(kept, u)
		}
		uris = kept
	}
	return uris, changed
}

// inferProductionHost extracts the production hostname from a client's
// existing redirect URIs. It looks for the first https:// URI whose path
// ends in /auth/callback.
func inferProductionHost(uris []string) string {
	for _, u := range uris {
		if strings.HasPrefix(u, "https://") && strings.HasSuffix(u, "/auth/callback") {
			// "https://books.codevertexafrica.com/auth/callback"
			// -> "books.codevertexafrica.com"
			trimmed := strings.TrimPrefix(u, "https://")
			host := strings.SplitN(trimmed, "/", 2)[0]
			return host
		}
	}
	return ""
}

func containsURI(uris []string, target string) bool {
	for _, u := range uris {
		if strings.EqualFold(strings.TrimSpace(u), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}
