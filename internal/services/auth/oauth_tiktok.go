package auth

import (
	"context"

	"golang.org/x/oauth2"

	tiktokprovider "github.com/bengobox/auth-api/internal/providers/tiktok"
)

// tiktokOAuth is what the sign-in flow needs from the TikTok provider (a fake in tests). TikTok
// runs through the shared social sign-in (social_oauth.go); the account is found by open_id only,
// because TikTok shares no email.
type tiktokOAuth interface {
	AuthCodeURL(ctx context.Context, state string) (string, error)
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchProfile(ctx context.Context, token *oauth2.Token) (*tiktokprovider.Profile, error)
}

// TikTokPlaceholderEmail mints the synthetic address for an account created by TikTok sign-in.
// TikTok shares no email, so the account gets a ".local" placeholder like a phone-only account,
// and the verify-email dialog asks the person for a real address (IsPlaceholderEmail).
func TikTokPlaceholderEmail(openID string) string {
	return socialPlaceholderEmail(tiktokProviderName, openID)
}

// tiktokIdentityProfile is the identity row's profile. union_id is kept so a second TikTok app
// of the same developer can be matched to the same person later.
func tiktokIdentityProfile(p *tiktokprovider.Profile) map[string]any {
	return map[string]any{
		"name":     p.DisplayName,
		"picture":  p.AvatarURL,
		"union_id": p.UnionID,
	}
}
