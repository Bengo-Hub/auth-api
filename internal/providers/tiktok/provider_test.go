package tiktok

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type fakeCreds struct {
	creds map[string]string
	err   error
}

func (f fakeCreds) GetDecryptedConfig(_ context.Context, tenantID *uuid.UUID, name string) (map[string]string, error) {
	if tenantID != nil {
		return nil, errors.New("tiktok config must be read at platform scope")
	}
	if name != IntegrationName {
		return nil, errors.New("unexpected integration " + name)
	}
	return f.creds, f.err
}

func testCreds() fakeCreds {
	return fakeCreds{creds: map[string]string{
		"client_key":    "test-client-key",
		"client_secret": "test-client-secret", // secret-scan:allow (fake fixture)
		"redirect_url":  "https://sso.example.test/api/v1/auth/oauth/tiktok/callback",
	}}
}

func TestAuthCodeURLUsesClientKey(t *testing.T) {
	p := newProvider(testCreds())
	raw, err := p.AuthCodeURL(context.Background(), "signed-state")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != defaultAuthorizeURL {
		t.Fatalf("authorize endpoint = %s", got)
	}
	q := u.Query()
	want := map[string]string{
		"client_key":    "test-client-key",
		"response_type": "code",
		"scope":         "user.info.basic",
		"redirect_uri":  "https://sso.example.test/api/v1/auth/oauth/tiktok/callback",
		"state":         "signed-state",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Has("client_id") {
		t.Error("TikTok takes client_key, client_id must not be sent")
	}
}

func TestConfigMissingFieldsRefused(t *testing.T) {
	p := newProvider(fakeCreds{creds: map[string]string{"client_key": "k"}})
	if _, err := p.AuthCodeURL(context.Background(), "s"); err == nil {
		t.Fatal("expected an error when client_secret and redirect_url are missing")
	}
	p = newProvider(fakeCreds{err: errors.New("disabled")})
	if _, err := p.AuthCodeURL(context.Background(), "s"); err == nil {
		t.Fatal("expected an error when the integration is disabled")
	}
}

func TestExchangeAndFetchProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/oauth/token/":
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("token content type = %s", ct)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"client_key":    "test-client-key",
				"client_secret": "test-client-secret", // secret-scan:allow (fake fixture)
				"code":          "auth-code",
				"grant_type":    "authorization_code",
				"redirect_uri":  "https://sso.example.test/api/v1/auth/oauth/tiktok/callback",
			}
			for k, v := range want {
				if r.PostForm.Get(k) != v {
					t.Errorf("token form %s = %q, want %q", k, r.PostForm.Get(k), v)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"act.123","expires_in":86400,"open_id":"open-abc","refresh_token":"rft.456","refresh_expires_in":31536000,"scope":"user.info.basic","token_type":"Bearer"}`))
		case "/v2/user/info/":
			if got := r.Header.Get("Authorization"); got != "Bearer act.123" {
				t.Errorf("user info auth = %q", got)
			}
			if got := r.URL.Query().Get("fields"); got != "open_id,union_id,avatar_url,display_name" {
				t.Errorf("fields = %q", got)
			}
			_, _ = w.Write([]byte(`{"data":{"user":{"open_id":"open-abc","union_id":"union-xyz","avatar_url":"https://p16.example/a.jpg","display_name":"Wanjiku"}},"error":{"code":"ok","message":"","log_id":"L1"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newProvider(testCreds())
	p.tokenURL = srv.URL + "/v2/oauth/token/"
	p.userInfoURL = srv.URL + "/v2/user/info/"

	tok, err := p.Exchange(context.Background(), "auth-code")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "act.123" || tok.Expiry.IsZero() {
		t.Fatalf("token = %+v", tok)
	}
	if tok.Extra("open_id") != "open-abc" || tok.Extra("scope") != "user.info.basic" {
		t.Fatalf("extras open_id=%v scope=%v", tok.Extra("open_id"), tok.Extra("scope"))
	}

	prof, err := p.FetchProfile(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if prof.OpenID != "open-abc" || prof.UnionID != "union-xyz" || prof.DisplayName != "Wanjiku" || prof.AvatarURL == "" {
		t.Fatalf("profile = %+v", prof)
	}
}

func TestExchangeErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Redirect_uri is not matched with the uri when requesting code.","log_id":"L2"}`))
	}))
	defer srv.Close()
	p := newProvider(testCreds())
	p.tokenURL = srv.URL
	_, err := p.Exchange(context.Background(), "bad")
	if err == nil || !strings.Contains(err.Error(), "invalid_request") || !strings.Contains(err.Error(), "L2") {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchProfileErrorAndOpenIDFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer expired" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"data":{},"error":{"code":"access_token_invalid","message":"The access token is invalid or not found in the request.","log_id":"L3"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"user":{"display_name":"No Id"}},"error":{"code":"ok"}}`))
	}))
	defer srv.Close()
	p := newProvider(testCreds())
	p.userInfoURL = srv.URL

	token := func(access, openID string) *oauth2.Token {
		return (&oauth2.Token{AccessToken: access}).WithExtra(map[string]any{"open_id": openID})
	}

	if _, err := p.FetchProfile(context.Background(), token("expired", "")); err == nil || !strings.Contains(err.Error(), "access_token_invalid") {
		t.Fatalf("err = %v", err)
	}

	prof, err := p.FetchProfile(context.Background(), token("good", "open-from-token"))
	if err != nil {
		t.Fatal(err)
	}
	if prof.OpenID != "open-from-token" {
		t.Fatalf("open_id fallback = %q", prof.OpenID)
	}

	if _, err := p.FetchProfile(context.Background(), token("good", "")); err == nil {
		t.Fatal("a profile without open_id must be refused")
	}
}
