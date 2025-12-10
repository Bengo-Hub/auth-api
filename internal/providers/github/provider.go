package github

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bengobox/auth-api/internal/config"
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
	cfg         config.GitHubProviderConfig
	oauthConfig *oauth2.Config
}

func New(cfg config.GitHubProviderConfig) (*Provider, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	return &Provider{
		cfg: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     githuboauth.Endpoint,
		},
	}, nil
}

func (p *Provider) AuthCodeURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (p *Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauthConfig.Exchange(ctx, code)
}

func (p *Provider) FetchProfile(ctx context.Context, token *oauth2.Token) (*Profile, error) {
	client := p.oauthConfig.Client(ctx, token)
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
