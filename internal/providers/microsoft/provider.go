package microsoft

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bengobox/auth-api/internal/services/integrations"
	"golang.org/x/oauth2"
)

const defaultTenant = "common"

type Profile struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
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
	creds, err := p.integrations.GetDecryptedConfig(ctx, nil, "microsoft")
	if err != nil {
		return nil, fmt.Errorf("microsoft integration not configured or disabled: %w", err)
	}

	tenant := creds["tenant_id"]
	if tenant == "" {
		tenant = defaultTenant
	}
	base := "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0"
	endpoint := oauth2.Endpoint{
		AuthURL:  base + "/authorize",
		TokenURL: base + "/token",
	}

	return &oauth2.Config{
		ClientID:     creds["client_id"],
		ClientSecret: creds["client_secret"],
		RedirectURL:  creds["redirect_url"],
		Scopes:       []string{"openid", "email", "profile", "User.Read"},
		Endpoint:     endpoint,
	}, nil
}

// AuthCodeURL constructs Microsoft authorization URL dynamically.
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
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		return nil, fmt.Errorf("ms graph: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ms graph status=%d", resp.StatusCode)
	}
	var prof Profile
	if err := json.NewDecoder(resp.Body).Decode(&prof); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &prof, nil
}
