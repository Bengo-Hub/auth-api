package google

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bengobox/auth-api/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Profile represents the minimal Google user info payload.
type Profile struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

// Provider wraps Google OAuth operations.
type Provider struct {
	cfg         config.GoogleProviderConfig
	oauthConfig *oauth2.Config
}

// New creates a Provider when Google OAuth is enabled. Returns nil if disabled.
func New(cfg config.GoogleProviderConfig) (*Provider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("google provider requires client id, secret, and redirect url")
	}

	return &Provider{
		cfg: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes: []string{
				"openid",
				"profile",
				"email",
			},
			Endpoint: google.Endpoint,
		},
	}, nil
}

// AuthCodeURL constructs the Google authorization URL.
func (p *Provider) AuthCodeURL(state string) string {
	return p.oauthConfig.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
}

// Exchange swaps the authorization code for tokens.
func (p *Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange google oauth code: %w", err)
	}
	return token, nil
}

// FetchProfile obtains the Google user info using the provided token.
func (p *Provider) FetchProfile(ctx context.Context, token *oauth2.Token) (*Profile, error) {
	client := p.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("fetch google profile: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("google profile request failed: status=%d", resp.StatusCode)
	}

	var profile Profile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode google profile: %w", err)
	}
	if profile.Subject == "" || profile.Email == "" {
		return nil, fmt.Errorf("google profile missing required fields")
	}
	return &profile, nil
}
