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
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
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

// SessionResult holds the session and refresh token created for OIDC flows.
type SessionResult struct {
	SessionID    uuid.UUID
	RefreshToken string
	ExpiresAt    time.Time
}

// CreateSession creates a new session with refresh token for the OIDC code exchange.
func (s *Service) CreateSession(ctx context.Context, userID uuid.UUID, clientID string, ipAddress, userAgent string) (*SessionResult, error) {
	refreshPlain, refreshHash, err := s.tokenSvc.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	expiresAt := time.Now().Add(s.cfg.Token.RefreshTokenTTL)
	sessionCreate := s.entClient.Session.Create().
		SetUserID(userID).
		SetRefreshTokenHash(refreshHash).
		SetSessionType("user").
		SetStatus("active").
		SetExpiresAt(expiresAt).
		SetClientID(clientID).
		SetIPAddress(ipAddress).
		SetUserAgent(userAgent)

	// Look up user's primary tenant
	user, err := s.entClient.User.Get(ctx, userID)
	if err == nil && user.PrimaryTenantID != "" {
		if tid, parseErr := uuid.Parse(user.PrimaryTenantID); parseErr == nil {
			sessionCreate.SetTenantID(tid)
		}
	}

	session, err := sessionCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &SessionResult{
		SessionID:    session.ID,
		RefreshToken: refreshPlain,
		ExpiresAt:    expiresAt,
	}, nil
}

// UserMembership holds a user's role and tenant information for a single tenant.
type UserMembership struct {
	TenantID   uuid.UUID
	TenantSlug string
	TenantName string
	Roles      []string
}

// GetUserMemberships returns the user's tenant memberships with tenant details.
func (s *Service) GetUserMemberships(ctx context.Context, userID uuid.UUID) ([]UserMembership, error) {
	memberships, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(userID)).
		WithTenant().
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("query memberships: %w", err)
	}
	result := make([]UserMembership, 0, len(memberships))
	for _, m := range memberships {
		um := UserMembership{
			TenantID: m.TenantID,
			Roles:    m.Roles,
		}
		if m.Edges.Tenant != nil {
			um.TenantSlug = m.Edges.Tenant.Slug
			um.TenantName = m.Edges.Tenant.Name
		}
		result = append(result, um)
	}
	return result, nil
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
		"phone":          firstProfileString(u.Profile, "phone", ""),
		"updated_at":     u.UpdatedAt.Unix(),
	}
}

// UserInfoPayloadFull builds a rich OIDC userinfo payload including tenant and role data.
func (s *Service) UserInfoPayloadFull(ctx context.Context, u *ent.User) map[string]any {
	payload := s.UserInfoPayload(u)

	memberships, err := s.GetUserMemberships(ctx, u.ID)
	if err == nil && len(memberships) > 0 {
		// Collect all roles across memberships
		var allRoles []string
		tenants := make([]map[string]any, 0, len(memberships))
		for _, m := range memberships {
			allRoles = append(allRoles, m.Roles...)
			tenants = append(tenants, map[string]any{
				"id":    m.TenantID.String(),
				"slug":  m.TenantSlug,
				"name":  m.TenantName,
				"roles": m.Roles,
			})
		}
		payload["roles"] = allRoles
		payload["tenants"] = tenants

		// Set primary tenant info
		if u.PrimaryTenantID != "" {
			payload["tenant_id"] = u.PrimaryTenantID
			for _, m := range memberships {
				if m.TenantID.String() == u.PrimaryTenantID {
					payload["tenant_slug"] = m.TenantSlug
					break
				}
			}
		}
	}

	return payload
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
