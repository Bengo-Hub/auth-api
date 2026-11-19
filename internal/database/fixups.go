package database

import (
	"context"
	"fmt"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
)

// runFixups applies the data changes the versioned migrations record. Each one is idempotent: once
// it has run, its UPDATE matches no rows, so running it on every start is cheap.
func runFixups(ctx context.Context, client *ent.Client) error {
	if err := ClearIdentityOAuthTokens(ctx, client); err != nil {
		return fmt.Errorf("fixup clear identity oauth tokens: %w", err)
	}
	return nil
}

// ClearIdentityOAuthTokens nulls the provider access and refresh tokens that social sign-in used
// to keep on user_identities (2026-11-19). Nothing reads them and sign-in no longer writes them.
// Mirrors migrations/20261119120000_clear_identity_oauth_tokens.sql.
func ClearIdentityOAuthTokens(ctx context.Context, client *ent.Client) error {
	return client.UserIdentity.Update().
		Where(useridentity.Or(useridentity.AccessTokenNotNil(), useridentity.RefreshTokenNotNil())).
		ClearAccessToken().
		ClearRefreshToken().
		Exec(ctx)
}
