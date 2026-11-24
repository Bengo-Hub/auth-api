package microsoft

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bengobox/auth-api/internal/services/integrations"
	"github.com/golang-jwt/jwt/v5"
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

// VerifiedEmail returns the ID token's email claim when Entra marks it domain-owner verified
// (the optional xms_edov claim, added under "Token configuration" in the app registration).
//
// Graph's mail and userPrincipalName are set by the person's own Entra tenant admin, who can type
// any address there, so they never prove ownership ("nOAuth"). Without xms_edov the email is not
// trusted and sign-in never matches an existing account by it.
//
// The ID token is read without a signature check: it comes straight from the token endpoint over
// TLS in the code exchange, which OpenID Connect Core 3.1.3.7 accepts in place of the signature.
func VerifiedEmail(token *oauth2.Token) (string, bool) {
	if token == nil {
		return "", false
	}
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return "", false
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return "", false
	}
	email, _ := claims["email"].(string)
	email = strings.TrimSpace(email)
	if email == "" || !claimTrue(claims["xms_edov"]) {
		return "", false
	}
	return email, true
}

// claimTrue reads a boolean claim Entra may send as true, "true" or "1".
func claimTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "1" || strings.EqualFold(t, "true")
	case float64:
		return t == 1
	}
	return false
}
