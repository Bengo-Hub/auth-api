// Package tiktok is the "Login with TikTok" provider (TikTok Login Kit for Web, OAuth v2).
//
// TikTok differs from the other providers in three ways: the app id is sent as client_key, not
// client_id; the token endpoint answers with open_id in the body; and the profile carries no
// email address. The account is identified by open_id, which TikTok scopes to this app.
// Web apps do not use PKCE (code_verifier is required only for mobile and desktop apps).
package tiktok

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/bengobox/auth-api/internal/services/integrations"
)

// IntegrationName is the integration_configs row (and catalog id in auth-ui) for TikTok.
const IntegrationName = "tiktok"

// Scope is the only scope sign-in needs: open_id, union_id, display_name and avatar.
const Scope = "user.info.basic"

const (
	defaultAuthorizeURL = "https://www.tiktok.com/v2/auth/authorize/"
	defaultTokenURL     = "https://open.tiktokapis.com/v2/oauth/token/"
	defaultUserInfoURL  = "https://open.tiktokapis.com/v2/user/info/"
	userInfoFields      = "open_id,union_id,avatar_url,display_name"
	maxBodyBytes        = 1 << 20
)

// Profile is the basic TikTok user. There is no email.
type Profile struct {
	OpenID      string `json:"open_id"`
	UnionID     string `json:"union_id"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

// credentialSource reads the decrypted platform integration config.
type credentialSource interface {
	GetDecryptedConfig(ctx context.Context, tenantID *uuid.UUID, name string) (map[string]string, error)
}

// Provider talks to TikTok with the platform credentials saved in integration_configs.
type Provider struct {
	creds        credentialSource
	httpClient   *http.Client
	authorizeURL string
	tokenURL     string
	userInfoURL  string
}

// New returns the provider backed by the encrypted integration config store.
func New(integrationSvc *integrations.Service) (*Provider, error) {
	return newProvider(integrationSvc), nil
}

func newProvider(src credentialSource) *Provider {
	return &Provider{
		creds:        src,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		authorizeURL: defaultAuthorizeURL,
		tokenURL:     defaultTokenURL,
		userInfoURL:  defaultUserInfoURL,
	}
}

type config struct {
	clientKey    string
	clientSecret string
	redirectURL  string
}

func (p *Provider) config(ctx context.Context) (*config, error) {
	creds, err := p.creds.GetDecryptedConfig(ctx, nil, IntegrationName)
	if err != nil {
		return nil, fmt.Errorf("tiktok integration not configured or disabled: %w", err)
	}
	c := &config{
		clientKey:    strings.TrimSpace(creds["client_key"]),
		clientSecret: strings.TrimSpace(creds["client_secret"]),
		redirectURL:  strings.TrimSpace(creds["redirect_url"]),
	}
	if c.clientKey == "" || c.clientSecret == "" || c.redirectURL == "" {
		return nil, errors.New("tiktok integration is missing client_key, client_secret or redirect_url")
	}
	return c, nil
}

// AuthCodeURL builds the TikTok authorize URL for the signed state.
func (p *Provider) AuthCodeURL(ctx context.Context, state string) (string, error) {
	c, err := p.config(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("client_key", c.clientKey)
	q.Set("response_type", "code")
	q.Set("scope", Scope)
	q.Set("redirect_uri", c.redirectURL)
	q.Set("state", state)
	return p.authorizeURL + "?" + q.Encode(), nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	OpenID           string `json:"open_id"`
	Scope            string `json:"scope"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	LogID            string `json:"log_id"`
}

// Exchange trades the authorization code for an access token. The token carries open_id and
// scope as extras so the caller can read them like any other provider's token.
func (p *Provider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	c, err := p.config(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("client_key", c.clientKey)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", c.redirectURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("tiktok token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tiktok token: %w", err)
	}
	defer resp.Body.Close()
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("tiktok token decode (status %d): %w", resp.StatusCode, err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("tiktok token: %s: %s (log_id %s)", tr.Error, tr.ErrorDescription, tr.LogID)
	}
	if resp.StatusCode >= 400 || tr.AccessToken == "" {
		return nil, fmt.Errorf("tiktok token status=%d: no access token", resp.StatusCode)
	}
	tok := &oauth2.Token{
		AccessToken:  tr.AccessToken,
		TokenType:    "Bearer",
		RefreshToken: tr.RefreshToken,
	}
	if tr.ExpiresIn > 0 {
		tok.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok.WithExtra(map[string]any{"open_id": tr.OpenID, "scope": tr.Scope}), nil
}

type userInfoResponse struct {
	Data struct {
		User Profile `json:"user"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		LogID   string `json:"log_id"`
	} `json:"error"`
}

// FetchProfile reads the basic profile. open_id falls back to the one the token response gave.
func (p *Provider) FetchProfile(ctx context.Context, token *oauth2.Token) (*Profile, error) {
	if token == nil || token.AccessToken == "" {
		return nil, errors.New("tiktok user: no access token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL+"?fields="+url.QueryEscape(userInfoFields), nil)
	if err != nil {
		return nil, fmt.Errorf("tiktok user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tiktok user: %w", err)
	}
	defer resp.Body.Close()
	var ur userInfoResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&ur); err != nil {
		return nil, fmt.Errorf("tiktok user decode (status %d): %w", resp.StatusCode, err)
	}
	if ur.Error.Code != "" && ur.Error.Code != "ok" {
		return nil, fmt.Errorf("tiktok user: %s: %s (log_id %s)", ur.Error.Code, ur.Error.Message, ur.Error.LogID)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("tiktok user status=%d", resp.StatusCode)
	}
	prof := ur.Data.User
	if prof.OpenID == "" {
		if id, ok := token.Extra("open_id").(string); ok {
			prof.OpenID = id
		}
	}
	if prof.OpenID == "" {
		return nil, errors.New("tiktok user: no open_id")
	}
	return &prof, nil
}
