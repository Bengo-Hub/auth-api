package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/userphone"
)

// VerifiedPhoneOf returns the verified phone (E.164) a platform service may send a one-time code
// to for userID: the primary verified phone, else the most recently verified one. An account that
// cannot sign in, or holds no verified phone, has none (ErrPhoneNotFound). Used by marketflow-api
// to send the boost confirmation code (2026-11-17).
func (s *Service) VerifiedPhoneOf(ctx context.Context, userID uuid.UUID) (string, error) {
	u, err := s.entClient.User.Get(ctx, userID)
	if ent.IsNotFound(err) {
		return "", ErrPhoneNotFound
	}
	if err != nil {
		return "", err
	}
	if !UserCanSignIn(u.Status) {
		return "", ErrPhoneNotFound
	}
	up, err := s.entClient.UserPhone.Query().
		Where(userphone.UserID(userID), userphone.IsVerifiedEQ(true)).
		Order(ent.Desc(userphone.FieldIsPrimary), ent.Desc(userphone.FieldVerifiedAt)).
		First(ctx)
	if ent.IsNotFound(err) {
		return "", ErrPhoneNotFound
	}
	if err != nil {
		return "", err
	}
	return up.Phone, nil
}

// ErrPhoneNotFound means no account holds the phone verified (or the account cannot sign in).
var ErrPhoneNotFound = errors.New("no user has this phone verified")

// PhoneUser is the S2S answer for a verified phone: the account and its active memberships.
type PhoneUser struct {
	UserID        uuid.UUID         `json:"user_id"`
	PhoneVerified bool              `json:"phone_verified"`
	Tenants       []PhoneUserTenant `json:"tenants"`
}

// PhoneUserTenant is one active membership of a PhoneUser.
type PhoneUserTenant struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Slug     string    `json:"slug"`
	Roles    []string  `json:"roles"`
}

// LookupVerifiedPhone finds the account that holds e164 VERIFIED, for a platform service that
// must decide whether a sender is a known user (marketflow-api's WhatsApp worker). An unverified
// row never matches: anyone can attach an unproven number to their own account, so matching it
// would let them pose as its holder. Accounts that cannot sign in are treated as unknown.
func (s *Service) LookupVerifiedPhone(ctx context.Context, e164 string) (*PhoneUser, error) {
	up, err := s.entClient.UserPhone.Query().
		Where(userphone.PhoneEQ(e164), userphone.IsVerifiedEQ(true)).
		WithUser().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrPhoneNotFound
	}
	if err != nil {
		return nil, err
	}
	if up.Edges.User == nil || !UserCanSignIn(up.Edges.User.Status) {
		return nil, ErrPhoneNotFound
	}
	members, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(up.UserID), tenantmembership.StatusEQ("active")).
		WithTenant().
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := &PhoneUser{UserID: up.UserID, PhoneVerified: true, Tenants: make([]PhoneUserTenant, 0, len(members))}
	for _, m := range members {
		t := PhoneUserTenant{TenantID: m.TenantID, Roles: m.Roles}
		if m.Edges.Tenant != nil {
			t.Slug = m.Edges.Tenant.Slug
		}
		if t.Roles == nil {
			t.Roles = []string{}
		}
		out.Tenants = append(out.Tenants, t)
	}
	return out, nil
}
