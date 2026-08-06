package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT registered claims plus auth specific metadata.
type Claims struct {
	SessionID   string   `json:"sid"`
	TenantID    string   `json:"tenant_id,omitempty"`
	TenantSlug  string   `json:"tenant_slug,omitempty"`
	Scope       []string `json:"scope,omitempty"`
	Roles       []string `json:"roles,omitempty"`       // User roles from TenantMembership (e.g., "superuser", "admin", "member")
	Permissions []string `json:"permissions,omitempty"` // Canonical permission codes for RBAC (e.g., "catalog:view", "orders:read")
	Email       string   `json:"email,omitempty"`
	// EmailVerified lets any downstream service gate access until the user has verified
	// their email (existing accounts are unverified until they complete the OTP flow).
	EmailVerified   bool `json:"email_verified,omitempty"`
	IsPlatformOwner bool `json:"is_platform_owner,omitempty"`

	// Outlet / branch context — set after the user selects an outlet at login.
	// Single-outlet tenants get this populated automatically; multi-outlet tenants
	// go through the select-outlet flow before receiving a JWT with these claims.
	OutletID      string `json:"outlet_id,omitempty"`
	OutletCode    string `json:"outlet_code,omitempty"`
	OutletUseCase string `json:"outlet_use_case,omitempty"`
	IsHQUser      bool   `json:"is_hq_user,omitempty"`

	// Subscription claims (enriched from subscription-service)
	SubscriptionPlan     string         `json:"sub_plan,omitempty"`              // Plan code (STARTER, GROWTH, PROFESSIONAL)
	SubscriptionStatus   string         `json:"sub_status,omitempty"`            // Status (ACTIVE, TRIAL, EXPIRED, etc.)
	SubscriptionFeatures []string       `json:"subscription_features,omitempty"` // Feature codes enabled for this plan (must match authclient Claims field)
	SubscriptionLimits   map[string]int `json:"sub_limits,omitempty"`            // Plan limits (max_outlets, max_riders, etc.)
	SubscriptionExpires  *int64         `json:"sub_expires,omitempty"`           // Current period end as Unix timestamp
	SubscriptionTier     int            `json:"sub_tier,omitempty"`              // Resolved plan tier rank (must match authclient Claims field); for backend tier-aware gating
	// ActiveProducts is the product_code of every currently-active per-product subscription
	// line (must match authclient Claims field) — lets the app-switcher show only activated
	// apps without a per-page-load network call.
	ActiveProducts []string `json:"active_products,omitempty"`

	// Billing model and demo flags
	BillingMode  string `json:"billing_mode,omitempty"`      // "service_charge" bypasses subscription gating
	IsDemo       bool   `json:"is_demo,omitempty"`           // true for demo tenant/users
	AllowOverage bool   `json:"sub_allow_overage,omitempty"` // tenant opted in to pay-as-you-go extra usage
	// SubscriptionExempt = platform-granted per-tenant exemption (auth-api Tenant.subscription_exempt).
	// Mirrors the shared-auth-client Claims field; bypasses ALL subscription gating downstream.
	SubscriptionExempt bool `json:"sub_exempt,omitempty"`

	jwt.RegisteredClaims
}

// AccessTokenInput defines metadata for token minting.
type AccessTokenInput struct {
	UserID     uuid.UUID
	TenantID   *uuid.UUID
	TenantSlug string
	SessionID  uuid.UUID
	Email      string
	// EmailVerified mirrors users.email_verified. Carried in the JWT so every service
	// (and PIN-issued terminal tokens) can require verification before granting access.
	EmailVerified   bool
	Scopes          []string
	Roles           []string // User roles from TenantMembership
	Permissions     []string // Canonical permission codes (e.g., catalog:view, orders:read)
	IsPlatformOwner bool
	Audience        []string

	// Outlet / branch context (optional — populated after outlet selection)
	OutletID      string
	OutletCode    string
	OutletUseCase string
	IsHQUser      bool

	// Subscription data (optional, from subscription-service)
	SubscriptionPlan     string
	SubscriptionStatus   string
	SubscriptionFeatures []string
	SubscriptionLimits   map[string]int
	SubscriptionExpires  *time.Time
	SubscriptionTier     int
	ActiveProducts       []string

	// Billing model and demo flags
	BillingMode        string // "service_charge" bypasses subscription gating
	IsDemo             bool   // true for demo tenant/users
	AllowOverage       bool   // tenant opted in to pay-as-you-go extra usage
	SubscriptionExempt bool   // platform-granted per-tenant subscription exemption
}

// Service handles JWT minting and verification.
type Service struct {
	cfg        config.TokenConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	parser     *jwt.Parser
	keyID      string
}

// NewService loads signing material and returns a token service.
func NewService(cfg config.TokenConfig) (*Service, error) {
	priv, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	pub, err := loadPublicKey(cfg.PublicKeyPath)
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:        cfg,
		privateKey: priv,
		publicKey:  pub,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		),
		keyID: computeKeyID(pub),
	}, nil
}

// ReloadFromFiles reloads key material from disk and updates key id.
func (s *Service) ReloadFromFiles() error {
	priv, err := loadPrivateKey(s.cfg.PrivateKeyPath)
	if err != nil {
		return err
	}
	pub, err := loadPublicKey(s.cfg.PublicKeyPath)
	if err != nil {
		return err
	}
	s.privateKey = priv
	s.publicKey = pub
	s.keyID = computeKeyID(pub)
	return nil
}

// MintAccessToken generates a signed JWT representing the authenticated user.
func (s *Service) MintAccessToken(input AccessTokenInput) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(s.cfg.AccessTokenTTL)
	jti := uuid.NewString()

	claims := &Claims{
		SessionID:       input.SessionID.String(),
		Scope:           input.Scopes,
		Roles:           input.Roles,
		Permissions:     input.Permissions,
		Email:           input.Email,
		EmailVerified:   input.EmailVerified,
		IsPlatformOwner: input.IsPlatformOwner,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			Subject:   input.UserID.String(),
			ID:        jti,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
		},
	}
	if input.TenantID != nil {
		claims.TenantID = input.TenantID.String()
	}
	if input.TenantSlug != "" {
		claims.TenantSlug = input.TenantSlug
	}
	if len(input.Audience) > 0 {
		claims.RegisteredClaims.Audience = jwt.ClaimStrings(input.Audience)
	}
	if input.OutletID != "" {
		claims.OutletID = input.OutletID
		claims.OutletCode = input.OutletCode
		claims.OutletUseCase = input.OutletUseCase
		claims.IsHQUser = input.IsHQUser
	}

	// Add subscription claims if available
	if input.SubscriptionPlan != "" {
		claims.SubscriptionPlan = input.SubscriptionPlan
		claims.SubscriptionStatus = input.SubscriptionStatus
		claims.SubscriptionFeatures = input.SubscriptionFeatures
		claims.SubscriptionLimits = input.SubscriptionLimits
		claims.SubscriptionTier = input.SubscriptionTier
		claims.ActiveProducts = input.ActiveProducts
		if input.SubscriptionExpires != nil {
			ts := input.SubscriptionExpires.Unix()
			claims.SubscriptionExpires = &ts
		}
	}
	if input.BillingMode != "" {
		claims.BillingMode = input.BillingMode
	}
	if input.IsDemo {
		claims.IsDemo = true
	}
	if input.AllowOverage {
		claims.AllowOverage = true
	}
	if input.SubscriptionExempt {
		claims.SubscriptionExempt = true
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	return signed, exp, nil
}

// Parse validates and parses a JWT token string.
func (s *Service) Parse(tokenString string) (*Claims, error) {
	token, err := s.parser.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("token invalid")
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("token claims mismatch")
	}
	return claims, nil
}

// GenerateRefreshToken returns a new opaque refresh token and its hashed value.
func (s *Service) GenerateRefreshToken() (plain string, hashed string, err error) {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("random refresh token: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	hashed = hex.EncodeToString(sum[:])
	return plain, hashed, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode private key pem: empty block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("parse private key: %v / %v", err, err2)
	}
	rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode public key pem: empty block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}
	return rsaPub, nil
}

// JWKS returns a minimal JWKS set for the active RSA public key.
func (s *Service) JWKS() map[string]any {
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes())
	jwk := map[string]any{
		"kty": "RSA",
		"kid": s.keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   n,
		"e":   e,
	}
	return map[string]any{
		"keys": []any{jwk},
	}
}

func computeKeyID(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(pub.N.Bytes())
	return hex.EncodeToString(sum[:8])
}

// KeyID exposes the current key ID.
func (s *Service) KeyID() string { return s.keyID }

// SignJWT signs arbitrary JWT claims using the active private key.
func (s *Service) SignJWT(claims map[string]any) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = s.keyID
	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	token.Claims = mc
	return token.SignedString(s.privateKey)
}
