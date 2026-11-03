package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
)

// Phone self-signup (platform task A1, Hadia SRDD FR-01). A tenant opts in through its metadata;
// every other tenant keeps the members-only phone sign-in. The code engine, rate limits and
// channels are the phone login's own: this file only decides who a verified phone becomes.
//
// Tenant metadata keys:
//   - phone_self_signup (bool): a verified phone that is on no account becomes a new member.
//   - self_signup_role (string): the role the new member gets; only self-service roles are
//     honoured and "customer" is the default.
//   - self_signup_services ([]string): the services granted to the new member
//     (TenantMembership.services, the user_services claim within the plan), e.g. ["hadia"].
const (
	tenantPhoneSelfSignupKey    = "phone_self_signup"
	tenantSelfSignupRoleKey     = "self_signup_role"
	tenantSelfSignupServicesKey = "self_signup_services"
	defaultPhoneSignupRole      = "customer"
)

// PhoneSignupPolicy is a tenant's phone self-signup setting.
type PhoneSignupPolicy struct {
	Role     string
	Services []string
}

// TenantPhoneSignupPolicy reads the tenant's opt-in. ok=false means phone self-signup is off.
// A staff role in the metadata is never honoured: the policy then falls back to "customer".
func TenantPhoneSignupPolicy(t *ent.Tenant) (PhoneSignupPolicy, bool) {
	if t == nil || t.Metadata == nil {
		return PhoneSignupPolicy{}, false
	}
	if on, _ := t.Metadata[tenantPhoneSelfSignupKey].(bool); !on {
		return PhoneSignupPolicy{}, false
	}
	role, _ := t.Metadata[tenantSelfSignupRoleKey].(string)
	role = strings.TrimSpace(role)
	if role == "" || role == "member" || !IsSelfServiceRole(role) {
		role = defaultPhoneSignupRole
	}
	return PhoneSignupPolicy{Role: role, Services: metadataStrings(t.Metadata[tenantSelfSignupServicesKey])}, true
}

// metadataStrings reads a JSON string list ([]any after decoding, or []string when set in code).
func metadataStrings(v any) []string {
	var out []string
	add := func(s string) {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, s)
		}
	}
	switch list := v.(type) {
	case []string:
		for _, s := range list {
			add(s)
		}
	case []any:
		for _, item := range list {
			if s, ok := item.(string); ok {
				add(s)
			}
		}
	}
	return out
}

// PhonePlaceholderEmail mints the synthetic address for a phone-only account. It ends in
// ".local", so isPlaceholderEmail treats it as replaceable by a real address later.
func PhonePlaceholderEmail(e164 string) string {
	return "p" + strings.TrimPrefix(e164, "+") + "@placeholder.local"
}

// signupTarget is the target for a phone the tenant lets sign up: no account yet (User nil),
// or a verified phone on an account that is not yet in the tenant (Join).
func signupTarget(t *ent.Tenant, phone string, policy PhoneSignupPolicy, existing *ent.User) *PhoneLoginTarget {
	return &PhoneLoginTarget{User: existing, Tenant: t, Phone: phone, Signup: &policy}
}

// completePhoneSignup turns a verified signup target into a member: a new phone-only account when
// the phone is on none, then the membership with the tenant's role and services. It runs only
// after the code check, so an unverified number never creates anything.
func (s *Service) completePhoneSignup(ctx context.Context, target *PhoneLoginTarget) error {
	policy := target.Signup
	if policy == nil {
		return ErrInvalidCredentials
	}
	if target.User == nil {
		u, err := s.createPhoneOnlyUser(ctx, target.Tenant, target.Phone)
		if err != nil {
			return err
		}
		target.User = u
	}
	if !UserCanSignIn(target.User.Status) {
		return ErrInvalidCredentials
	}
	_, err := s.joinTenantWith(ctx, target.User, target.Tenant, policy.Role, policy.Services, "phone_self_signup")
	return err
}

// createPhoneOnlyUser creates the account and its verified primary phone in one transaction, so a
// failure never leaves an account without the phone that signs it in. The password stays empty:
// the account signs in by phone code (or a password set later through reset).
func (s *Service) createPhoneOnlyUser(ctx context.Context, t *ent.Tenant, phone string) (*ent.User, error) {
	email := PhonePlaceholderEmail(phone)
	if taken, err := s.entClient.User.Query().Where(user.EmailEQ(email)).Exist(ctx); err != nil {
		return nil, err
	} else if taken {
		// A placeholder minted earlier for this number now belongs to an account that lost the
		// phone; a suffix keeps the new address unique.
		email = strings.TrimSuffix(email, "@placeholder.local") + "-" + uuid.NewString()[:8] + "@placeholder.local"
	}
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	u, err := tx.User.Create().
		SetEmail(email).
		SetStatus(UserStatusActive).
		SetPrimaryTenantID(t.ID.String()).
		SetProfile(map[string]any{"phone": phone, "signup_method": "phone_otp"}).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("phone signup: create user: %w", err)
	}
	if _, err := tx.UserPhone.Create().
		SetUserID(u.ID).SetPhone(phone).SetIsPrimary(true).SetIsVerified(true).SetVerifiedAt(now).
		Save(ctx); err != nil {
		_ = tx.Rollback()
		if ent.IsConstraintError(err) {
			// Another request registered the number first; the caller answers as for any miss.
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("phone signup: store phone: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.logger.Info("phone self-signup: account created", zap.String("tenant", t.Slug),
		zap.String("user_id", u.ID.String()), zap.String("phone", maskPhone(phone)))
	return u, nil
}

// hasAnyMembership reports whether the user has a membership in the tenant in any status. A
// suspended or removed member is never re-activated by a phone code.
func (s *Service) hasAnyMembership(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(userID), tenantmembership.TenantID(tenantID)).
		Exist(ctx)
}
