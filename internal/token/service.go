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

	"github.com/bengobox/auth-service/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT registered claims plus auth specific metadata.
type Claims struct {
	SessionID string   `json:"sid"`
	TenantID  string   `json:"tenant_id,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	Roles     []string `json:"roles,omitempty"` // User roles from TenantMembership (e.g., "superuser", "admin", "member")
	Email     string   `json:"email,omitempty"`
	jwt.RegisteredClaims
}

// AccessTokenInput defines metadata for token minting.
type AccessTokenInput struct {
	UserID    uuid.UUID
	TenantID  *uuid.UUID
	SessionID uuid.UUID
	Email     string
	Scopes    []string
	Roles     []string // User roles from TenantMembership
	Audience  []string
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
		SessionID: input.SessionID.String(),
		Scope:     input.Scopes,
		Roles:     input.Roles,
		Email:     input.Email,
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
	if len(input.Audience) > 0 {
		claims.RegisteredClaims.Audience = jwt.ClaimStrings(input.Audience)
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
