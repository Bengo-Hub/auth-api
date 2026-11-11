package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/services/usecase"
)

// Business invites (owner, 2026-11-11): a platform owner invites a NEW business to an app. The
// invitee signs up through SSO with the invite and their organisation is created active, skipping
// the platform review every self-registered organisation waits for (that review stays for sign-ups
// without an invite: security audit M1, invite only). The invite is a signed token, not a row:
// nothing to migrate. It is single use: the organisation it creates records the invite id in its
// metadata, and a second organisation for the same invite is refused.

// BusinessInviteTTL is how long an invite link works.
const BusinessInviteTTL = 7 * 24 * time.Hour

// MetaBusinessInvite is the tenant metadata key that records the invite that created it.
const MetaBusinessInvite = "business_invite_id"

// BusinessInviteApps are the apps a business can be invited to.
var BusinessInviteApps = map[string]bool{"marketflow": true}

var ErrInvalidBusinessInvite = errors.New("this invitation link is invalid or has expired")

// BusinessInvite is what an invite says.
type BusinessInvite struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	OrgName   string    `json:"org_name"`
	UseCase   string    `json:"use_case,omitempty"`
	App       string    `json:"app"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (b *BusinessInvite) matches(email string) bool {
	return b != nil && strings.EqualFold(strings.TrimSpace(email), b.Email)
}

type businessInviteClaims struct {
	Purpose string `json:"purpose"`
	Email   string `json:"email"`
	OrgName string `json:"org_name"`
	UseCase string `json:"use_case,omitempty"`
	App     string `json:"app"`
	jwt.RegisteredClaims
}

const businessInvitePurpose = "business_invite"

// businessInviteKey derives a key used for nothing else from the service secret.
func businessInviteKey(secret string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("codevertex/auth/business-invite/v1"))
	return m.Sum(nil)
}

func validateBusinessInvite(in BusinessInvite) (BusinessInvite, error) {
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	in.OrgName = strings.TrimSpace(in.OrgName)
	in.UseCase = strings.TrimSpace(in.UseCase)
	in.App = strings.TrimSpace(in.App)
	if a, err := mail.ParseAddress(in.Email); err != nil || a.Address != in.Email {
		return in, fmt.Errorf("a valid email is required")
	}
	if in.OrgName == "" || len([]rune(in.OrgName)) > 120 {
		return in, fmt.Errorf("the organisation name is required (at most 120 characters)")
	}
	if !BusinessInviteApps[in.App] {
		return in, fmt.Errorf("unknown app %q", in.App)
	}
	if in.UseCase != "" && usecase.Lookup(in.UseCase) == nil {
		return in, fmt.Errorf("unknown business type %q", in.UseCase)
	}
	return in, nil
}

func signBusinessInvite(secret string, in BusinessInvite, ttl time.Duration) (string, BusinessInvite, error) {
	in, err := validateBusinessInvite(in)
	if err != nil {
		return "", in, err
	}
	now := time.Now()
	in.ID = uuid.NewString()
	in.ExpiresAt = now.Add(ttl)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, businessInviteClaims{
		Purpose: businessInvitePurpose, Email: in.Email, OrgName: in.OrgName, UseCase: in.UseCase, App: in.App,
		RegisteredClaims: jwt.RegisteredClaims{ID: in.ID, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(in.ExpiresAt)},
	}).SignedString(businessInviteKey(secret))
	return tok, in, err
}

func parseBusinessInvite(secret, token string) (*BusinessInvite, error) {
	var c businessInviteClaims
	_, err := jwt.ParseWithClaims(strings.TrimSpace(token), &c, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidBusinessInvite
		}
		return businessInviteKey(secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil || c.Purpose != businessInvitePurpose || c.ID == "" || !BusinessInviteApps[c.App] {
		return nil, ErrInvalidBusinessInvite
	}
	out := &BusinessInvite{ID: c.ID, Email: strings.ToLower(c.Email), OrgName: c.OrgName, UseCase: c.UseCase, App: c.App}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}

// IssueBusinessInvite signs an invite. The caller (a platform-owner-only handler) sends it.
func (s *Service) IssueBusinessInvite(in BusinessInvite) (string, BusinessInvite, error) {
	if s.cfg.Security.OAuthStateSecret == "" {
		return "", in, fmt.Errorf("business invites need OAUTH_STATE_SECRET")
	}
	return signBusinessInvite(s.cfg.Security.OAuthStateSecret, in, BusinessInviteTTL)
}

// redeemBusinessInvite checks an invite at sign-up: valid, for this email, and not yet used.
func (s *Service) redeemBusinessInvite(ctx context.Context, token, email string) (*BusinessInvite, error) {
	inv, err := parseBusinessInvite(s.cfg.Security.OAuthStateSecret, token)
	if err != nil || !inv.matches(email) {
		return nil, ErrInvalidBusinessInvite
	}
	used, err := s.entClient.Tenant.Query().Where(func(sel *sql.Selector) {
		sel.Where(sqljson.ValueEQ(tenant.FieldMetadata, inv.ID, sqljson.Path(MetaBusinessInvite)))
	}).Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("check invite: %w", err)
	}
	if used {
		return nil, ErrInvalidBusinessInvite
	}
	return inv, nil
}
