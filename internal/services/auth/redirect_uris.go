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
	clients, err := entClient.OAuthClient.Query().All(ctx)
	if err != nil {
		return err
	}

	for _, c := range clients {
		prodHost := inferProductionHost(c.RedirectUris)
		if prodHost == "" {
			continue
		}

		prodURI := "https://" + prodHost + "/" + tenantSlug + "/auth/callback"
		localURI := "http://localhost:3000/" + tenantSlug + "/auth/callback"

		var added bool
		uris := c.RedirectUris
		if !containsURI(uris, prodURI) {
			uris = append(uris, prodURI)
			added = true
		}
		if !containsURI(uris, localURI) {
			uris = append(uris, localURI)
			added = true
		}
		if !added {
			continue
		}

		if _, err := c.Update().SetRedirectUris(uris).Save(ctx); err != nil {
			return err
		}
	}
	return nil
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
