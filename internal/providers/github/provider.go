package github

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bengobox/auth-api/internal/services/integrations"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
)

type Profile struct {
	ID     int64  `json:"id"`
	Login  string `json:"login"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Avatar string `json:"avatar_url"`
}

type emailRecord struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

type Provider struct {
	integrations *integrations.Service
}

func New(integrationSvc *integrations.Service) (*Provider, error) {
	return &Provider{
		integrations: integrationSvc,
	}, nil
}

func (p *Provider) getOAuthConfig(ctx context.Context) (*oauth2.Config, error) {
	creds, err := p.integrations.GetDecryptedConfig(ctx, nil, "github")
	if err != nil {
		return nil, fmt.Errorf("github integration not configured or disabled: %w", err)
	}

	return &oauth2.Config{
		ClientID:     creds["client_id"],
		ClientSecret: creds["client_secret"],
		RedirectURL:  creds["redirect_url"],
		Scopes:       []string{"read:user", "user:email"},
		Endpoint:     githuboauth.Endpoint,
	}, nil
}

func (p *Provider) AuthCodeURL(ctx context.Context, state string) (string, error) {
	oc, err := p.getOAuthConfig(ctx)
	if err != nil {
		return "", err
	}
	return oc.AuthCodeURL(state, oauth2.AccessTypeOnline), nil
}

func (p *Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	oc, err := p.getOAuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	return oc.Exchange(ctx, code)
}

func (p *Provider) FetchProfile(ctx context.Context, token *oauth2.Token) (*Profile, error) {
	oc, err := p.getOAuthConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := oc.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("github user status=%d", resp.StatusCode)
	}
	var prof Profile
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		return nil, fmt.Errorf("github decode: %w", err)
	}
	// email might be empty; fetch emails
	if prof.Email == "" {
		emailsResp, err := client.Get("https://api.github.com/user/emails")
		if err == nil && emailsResp.StatusCode < 400 {
			defer emailsResp.Body.Close()
			var emails []emailRecord
			if json.NewDecoder(emailsResp.Body).Decode(&emails) == nil {
				for _, e := range emails {
					if e.Primary && e.Verified {
						prof.Email = e.Email
						break
					}
				}
				if prof.Email == "" && len(emails) > 0 {
					prof.Email = emails[0].Email
				}
			}
		}
	}
	return &prof, nil
}
