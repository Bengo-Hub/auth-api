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
	// VerifiedEmail is the primary address from /user/emails when GitHub marks it verified. It is
	// the only address sign-in may match an existing account by.
	VerifiedEmail string `json:"-"`
}

// EmailRecord is one entry of GET /user/emails.
type EmailRecord struct {
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
	// The public profile email is whatever the person typed into their profile and GitHub does not
	// promise it is verified. Only the primary address that /user/emails marks verified is proof of
	// ownership, so it is always fetched and kept apart.
	emailsResp, err := client.Get("https://api.github.com/user/emails")
	if err == nil {
		defer emailsResp.Body.Close()
		if emailsResp.StatusCode < 400 {
			var emails []EmailRecord
			if json.NewDecoder(emailsResp.Body).Decode(&emails) == nil {
				prof.VerifiedEmail = PrimaryVerifiedEmail(emails)
			}
		}
	}
	return &prof, nil
}

// PrimaryVerifiedEmail is the primary address when GitHub has verified it, else "".
func PrimaryVerifiedEmail(emails []EmailRecord) string {
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	return ""
}
