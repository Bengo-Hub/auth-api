package auth

import (
	"context"
	"strings"

	"github.com/bengobox/auth-api/internal/ent"
)

// AppendTenantRedirectURIs adds tenant-slug-specific redirect URIs to all
// public OAuth clients. Called automatically when a new tenant is created
// (via registration or admin API) so that the new tenant's /{slug}/auth/callback
// paths are immediately valid without re-running the seed.
func AppendTenantRedirectURIs(ctx context.Context, entClient *ent.Client, tenantSlug string) error {
	return syncTenantRedirectURIs(ctx, entClient, tenantSlug, "")
}

// RenameTenantRedirectURIs moves a renamed tenant's redirect URIs from the old slug to the new one
// on every OAuth client: the new /{slug}/auth/callback URIs are added and the old slug's are
// removed, so a stale slug cannot keep receiving authorization codes. Idempotent.
func RenameTenantRedirectURIs(ctx context.Context, entClient *ent.Client, oldSlug, newSlug string) error {
	return syncTenantRedirectURIs(ctx, entClient, newSlug, oldSlug)
}

// tenantRedirectURIs are the callback URIs one tenant slug owns on a client with production host.
func tenantRedirectURIs(prodHost, slug string) (prod, local string) {
	return "https://" + prodHost + "/" + slug + "/auth/callback", "http://localhost:3000/" + slug + "/auth/callback"
}

// syncTenantRedirectURIs ensures addSlug's URIs exist on every client that has a production
// callback host, and drops removeSlug's (when set and different) in the same write.
func syncTenantRedirectURIs(ctx context.Context, entClient *ent.Client, addSlug, removeSlug string) error {
	clients, err := entClient.OAuthClient.Query().All(ctx)
	if err != nil {
		return err
	}

	for _, c := range clients {
		uris, changed := nextRedirectURIs(c.RedirectUris, addSlug, removeSlug)
		if !changed {
			continue
		}
		if _, err := c.Update().SetRedirectUris(uris).Save(ctx); err != nil {
			return err
		}
	}
	return nil
}

// nextRedirectURIs returns a client's redirect URIs with addSlug's callbacks present and
// removeSlug's gone, and whether anything changed. Clients without a production callback host
// (no https .../auth/callback URI) are left alone.
func nextRedirectURIs(current []string, addSlug, removeSlug string) ([]string, bool) {
	prodHost := inferProductionHost(current)
	if prodHost == "" {
		return current, false
	}
	changed := false
	uris := append([]string(nil), current...)
	addProd, addLocal := tenantRedirectURIs(prodHost, addSlug)
	for _, u := range []string{addProd, addLocal} {
		if !containsURI(uris, u) {
			uris = append(uris, u)
			changed = true
		}
	}
	if removeSlug != "" && !strings.EqualFold(removeSlug, addSlug) {
		oldProd, oldLocal := tenantRedirectURIs(prodHost, removeSlug)
		kept := uris[:0]
		for _, u := range uris {
			if strings.EqualFold(strings.TrimSpace(u), oldProd) || strings.EqualFold(strings.TrimSpace(u), oldLocal) {
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
