package google

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bengobox/auth-api/internal/services/integrations"
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
	integrations *integrations.Service
}

// New creates a Provider that resolves config dynamically.
func New(integrationSvc *integrations.Service) (*Provider, error) {
	return &Provider{
		integrations: integrationSvc,
	}, nil
}

func (p *Provider) getOAuthConfig(ctx context.Context) (*oauth2.Config, error) {
	creds, err := p.integrations.GetDecryptedConfig(ctx, nil, "google")
	if err != nil {
		return nil, fmt.Errorf("google integration not configured or disabled: %w", err)
	}

	return &oauth2.Config{
		ClientID:     creds["client_id"],
		ClientSecret: creds["client_secret"],
		RedirectURL:  creds["redirect_url"],
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
		Endpoint: google.Endpoint,
	}, nil
}

// AuthCodeURL constructs the Google authorization URL dynamically.
func (p *Provider) AuthCodeURL(ctx context.Context, state string) (string, error) {
	oc, err := p.getOAuthConfig(ctx)
	if err != nil {
		return "", err
	}
	return oc.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	), nil
}

// Exchange swaps the authorization code for tokens dynamically.
func (p *Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	oc, err := p.getOAuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	token, err := oc.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange google oauth code: %w", err)
	}
	return token, nil
}

// FetchProfile obtains the Google user info using the provided token.
func (p *Provider) FetchProfile(ctx context.Context, token *oauth2.Token) (*Profile, error) {
	oc, err := p.getOAuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := oc.Client(ctx, token)
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
