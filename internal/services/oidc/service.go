package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/authorizationcode"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/google/uuid"
)

// Service encapsulates OIDC validation and code exchange.
type Service struct {
	entClient *ent.Client
	tokenSvc  *token.Service
	cfg       *config.Config
}

// New constructs an OIDC service.
func New(entClient *ent.Client, tokenSvc *token.Service, cfg *config.Config) *Service {
	return &Service{
		entClient: entClient,
		tokenSvc:  tokenSvc,
		cfg:       cfg,
	}
}

// ClientByID returns the OAuth client by client_id.
func (s *Service) ClientByID(ctx context.Context, clientID string) (*ent.OAuthClient, error) {
	return s.entClient.OAuthClient.Query().
		Where(oauthclient.ClientIDEQ(clientID)).
		Only(ctx)
}

// ValidateRedirect ensures redirect URI is registered for client.
func (s *Service) ValidateRedirect(client *ent.OAuthClient, redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	for _, allowed := range client.RedirectUris {
		if strings.EqualFold(strings.TrimSpace(allowed), strings.TrimSpace(redirectURI)) {
			return true
		}
	}
	return false
}

// CreateAuthorizationCode creates and stores an auth code with PKCE details.
func (s *Service) CreateAuthorizationCode(ctx context.Context, userID uuid.UUID, clientID, redirectURI, scope, nonce, code, codeChallenge, codeChallengeMethod string) (*ent.AuthorizationCode, error) {
	codeHash := sha256.Sum256([]byte(code))
	builder := s.entClient.AuthorizationCode.Create().
		SetUserID(userID).
		SetClientID(clientID).
		SetRedirectURI(redirectURI).
		SetScope(scope).
		SetNonce(nonce).
		SetCodeHash(hex.EncodeToString(codeHash[:])).
		SetCodeChallenge(codeChallenge).
		SetCodeChallengeMethod(strings.ToLower(codeChallengeMethod)).
		SetExpiresAt(time.Now().Add(5 * time.Minute))
	return builder.Save(ctx)
}

// ExchangeCode validates the code and returns user + client after consuming it.
func (s *Service) ExchangeCode(ctx context.Context, codePlain, clientID, redirectURI, codeVerifier string) (*ent.User, *ent.OAuthClient, *ent.AuthorizationCode, error) {
	hash := sha256.Sum256([]byte(codePlain))
	code, err := s.entClient.AuthorizationCode.Query().
		Where(
			authorizationcode.CodeHashEQ(hex.EncodeToString(hash[:])),
			authorizationcode.ClientIDEQ(clientID),
			authorizationcode.ConsumedAtIsNil(),
		).
		WithUser().
		Only(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("code not found: %w", err)
	}
	if !code.ExpiresAt.After(time.Now()) {
		return nil, nil, nil, fmt.Errorf("code expired")
	}
	if !strings.EqualFold(code.RedirectURI, redirectURI) {
		return nil, nil, nil, fmt.Errorf("redirect mismatch")
	}
	// PKCE validation when code challenge present
	if code.CodeChallenge != "" {
		// S256 required by spec when present
		verifierHash := sha256.Sum256([]byte(codeVerifier))
		encoded := base64URLEncode(verifierHash[:])
		if !strings.EqualFold(encoded, code.CodeChallenge) {
			return nil, nil, nil, fmt.Errorf("pkce verification failed")
		}
	}
	userEntity := code.Edges.User
	if userEntity == nil {
		loaded, err := s.entClient.User.Get(ctx, code.UserID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load user: %w", err)
		}
		userEntity = loaded
	}
	client, err := s.ClientByID(ctx, clientID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load client: %w", err)
	}
	// consume
	if err := s.entClient.AuthorizationCode.UpdateOneID(code.ID).
		SetConsumedAt(time.Now()).
		Exec(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("consume code: %w", err)
	}
	return userEntity, client, code, nil
}

// UserInfoPayload builds OIDC userinfo payload from user.
func (s *Service) UserInfoPayload(u *ent.User) map[string]any {
	sub := u.ID.String()
	email := u.Email
	emailVerified := true
	if raw, err := json.Marshal(u.Profile); err == nil {
		_ = raw // reserved for future mapping
	}
	return map[string]any{
		"sub":            sub,
		"email":          email,
		"email_verified": emailVerified,
		"name":           firstProfileString(u.Profile, "name", email),
		"updated_at":     u.UpdatedAt.Unix(),
	}
}

// GetUserByID fetches user by ID.
func (s *Service) GetUserByID(ctx context.Context, id uuid.UUID) (*ent.User, error) {
	return s.entClient.User.Get(ctx, id)
}

func firstProfileString(profile map[string]any, key, fallback string) string {
	if profile == nil {
		return fallback
	}
	if v, ok := profile[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return fallback
}

func base64URLEncode(b []byte) string {
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var result strings.Builder
	var val uint
	var valb int
	for _, c := range b {
		val = (val << 8) | uint(c)
		valb += 8
		for valb >= 6 {
			result.WriteByte(encodeURL[(val>>(uint(valb)-6))&0x3F])
			valb -= 6
		}
	}
	if valb > 0 {
		result.WriteByte(encodeURL[(val<<(6-uint(valb)))&0x3F])
	}
	// no padding
	return result.String()
}
