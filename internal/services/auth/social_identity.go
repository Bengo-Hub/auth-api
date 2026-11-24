package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
)

var (
	// ErrSocialEmailInUse: the provider gave an email it does not vouch for, and an account already
	// uses it. Matching on it would hand that account to whoever controls the provider profile.
	ErrSocialEmailInUse = errors.New("an account with this email already exists: sign in with your email, then link this provider in Account settings")
	// ErrSocialIdentityLinkedElsewhere: the provider account already signs in to another person.
	ErrSocialIdentityLinkedElsewhere = errors.New("this sign-in account is already linked to a different Codevertex account")
	// ErrSocialLinkSessionMismatch: the link callback did not come from the browser of the person who
	// started it (no session, another person's session, or a tampered state).
	ErrSocialLinkSessionMismatch = errors.New("sign in again, then link the account from Account settings")
	// ErrSocialIdentityNotFound: no such linked sign-in method on this account.
	ErrSocialIdentityNotFound = errors.New("sign-in method not found")
	// ErrLastSignInMethod: unlinking would leave the account with no way to sign in.
	ErrLastSignInMethod = errors.New("this is your only way to sign in: set a password or link another account first")
)

// SocialLinkError marks a failure of the link flow, so the callback returns the person to Account
// settings instead of the sign-in page.
type SocialLinkError struct {
	Provider string
	Err      error
}

func (e *SocialLinkError) Error() string { return e.Err.Error() }
func (e *SocialLinkError) Unwrap() error { return e.Err }

// socialPlaceholderEmail is the address of an account a provider created without an email it
// vouches for. It is stable per provider account, and the verify-email dialog asks the person for a
// real address (IsPlaceholderEmail).
func socialPlaceholderEmail(provider, subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return provider + "-" + hex.EncodeToString(sum[:8]) + "@placeholder.local"
}

// resolveSocialUser is the one account resolver of every social sign-in:
//  1. the provider identity is already linked: that account, whatever its email
//  2. otherwise a TRUSTED provider email matches an existing account: link it there
//  3. an untrusted email that an account already uses is refused with a hint to link instead
//  4. otherwise a new account (a placeholder address when there is no trusted email)
//
// ensureMembership then decides whether the person may be in the tenant. An existing account is
// returned with the refusal (the caller may fall back to the person's home tenant); a new account
// that is refused is deleted again, so a refused sign-up leaves nothing behind.
func (s *Service) resolveSocialUser(ctx context.Context, tenantEntity *ent.Tenant, joinRole string, sp *SocialProfile) (*ent.User, error) {
	identity, err := s.entClient.UserIdentity.Query().
		Where(useridentity.ProviderEQ(sp.Provider), useridentity.ProviderSubjectEQ(sp.Subject)).
		WithUser().
		Only(ctx)
	if err == nil {
		userEntity := identity.Edges.User
		if userEntity == nil {
			if userEntity, err = s.entClient.User.Get(ctx, identity.UserID); err != nil {
				return nil, fmt.Errorf("load user for identity: %w", err)
			}
		}
		if !s.isDomainAllowed(userEntity.Email) && !(sp.EmailTrusted && s.isDomainAllowed(sp.Email)) {
			return nil, ErrEmailDomainNotAllowed
		}
		if err := s.ensureMembership(ctx, userEntity, tenantEntity, joinRole); err != nil {
			return userEntity, err
		}
		if err := s.updateIdentity(ctx, identity.ID, sp); err != nil {
			return nil, err
		}
		s.setPrimaryTenantIfEmpty(ctx, userEntity, tenantEntity)
		return userEntity, nil
	}
	if !ent.IsNotFound(err) {
		return nil, fmt.Errorf("query user identity: %w", err)
	}

	if sp.Email != "" {
		existing, err := s.entClient.User.Query().Where(user.EmailEQ(sp.Email)).Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return nil, fmt.Errorf("lookup user by email: %w", err)
		}
		if existing != nil {
			if !sp.EmailTrusted {
				return nil, ErrSocialEmailInUse
			}
			return s.linkByTrustedEmail(ctx, existing, tenantEntity, joinRole, sp)
		}
	}
	return s.createSocialUser(ctx, tenantEntity, joinRole, sp)
}

// linkByTrustedEmail links the provider to the account that owns the provider-verified email.
// The identity is linked before the membership check: the email proves it is the same person,
// whichever tenant they may enter.
func (s *Service) linkByTrustedEmail(ctx context.Context, userEntity *ent.User, tenantEntity *ent.Tenant, joinRole string, sp *SocialProfile) (*ent.User, error) {
	if !s.isDomainAllowed(sp.Email) {
		return nil, ErrEmailDomainNotAllowed
	}
	if err := s.createIdentity(ctx, userEntity.ID, sp); err != nil {
		return nil, err
	}
	if !userEntity.EmailVerified {
		// The provider proved the address, so the verify-email banner can go.
		if u, err := userEntity.Update().SetEmailVerified(true).SetEmailVerifiedAt(time.Now()).Save(ctx); err == nil {
			userEntity = u
		}
	}
	if err := s.ensureMembership(ctx, userEntity, tenantEntity, joinRole); err != nil {
		return userEntity, err
	}
	s.setPrimaryTenantIfEmpty(ctx, userEntity, tenantEntity)
	return userEntity, nil
}

// createSocialUser makes the account of a person new to the platform.
func (s *Service) createSocialUser(ctx context.Context, tenantEntity *ent.Tenant, joinRole string, sp *SocialProfile) (*ent.User, error) {
	email := sp.Email
	if !sp.EmailTrusted || email == "" {
		email = socialPlaceholderEmail(sp.Provider, sp.Subject)
		if taken, err := s.entClient.User.Query().Where(user.EmailEQ(email)).Exist(ctx); err != nil {
			return nil, fmt.Errorf("lookup user: %w", err)
		} else if taken {
			email = strings.TrimSuffix(email, "@placeholder.local") + "-" + uuid.NewString()[:8] + "@placeholder.local"
		}
	}
	if !s.isDomainAllowed(email) {
		// Sign-in is locked to named email domains; a placeholder address never qualifies.
		return nil, ErrEmailDomainNotAllowed
	}
	profile := map[string]any{"signup_method": sp.Provider}
	if name := strings.TrimSpace(sp.Name); name != "" {
		profile["name"] = name
	}
	if sp.Picture != "" {
		profile["picture"] = sp.Picture
	}
	if locale, _ := sp.Profile["locale"].(string); locale != "" {
		profile["locale"] = locale
	}
	create := s.entClient.User.Create().
		SetEmail(email).
		SetStatus(UserStatusActive).
		SetPrimaryTenantID(tenantEntity.ID.String()).
		SetProfile(profile)
	if email == sp.Email && sp.EmailTrusted {
		create = create.SetEmailVerified(true).SetEmailVerifiedAt(time.Now())
	}
	userEntity, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create user from %s profile: %w", sp.Provider, err)
	}
	if err := s.ensureMembership(ctx, userEntity, tenantEntity, joinRole); err != nil {
		s.removeRefusedSignup(ctx, userEntity)
		return nil, err
	}
	if err := s.createIdentity(ctx, userEntity.ID, sp); err != nil {
		return nil, err
	}
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"full_name":   profileStr(userEntity.Profile, "name"),
		"phone":       profileStr(userEntity.Profile, "phone"),
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"roles":       []string{joinRole},
		"method":      sp.Provider,
	})
	return userEntity, nil
}

// removeRefusedSignup deletes an account made a moment ago for a sign-up the membership policy refused.
func (s *Service) removeRefusedSignup(ctx context.Context, userEntity *ent.User) {
	if err := s.entClient.User.DeleteOneID(userEntity.ID).Exec(ctx); err != nil {
		s.logger.Warn("social sign-up: could not remove refused account", zap.String("user_id", userEntity.ID.String()), zap.Error(err))
	}
}

func (s *Service) setPrimaryTenantIfEmpty(ctx context.Context, userEntity *ent.User, tenantEntity *ent.Tenant) {
	if userEntity.PrimaryTenantID != "" {
		return
	}
	if err := s.entClient.User.UpdateOneID(userEntity.ID).SetPrimaryTenantID(tenantEntity.ID.String()).Exec(ctx); err != nil {
		s.logger.Warn("failed to set primary tenant from oauth", zap.Error(err))
	}
}

// identityEmail is the provider_email column (required): the provider's address, or the
// placeholder for a provider that shares none.
func identityEmail(sp *SocialProfile) string {
	if sp.Email != "" {
		return sp.Email
	}
	return socialPlaceholderEmail(sp.Provider, sp.Subject)
}

// createIdentity links a provider account to the user, under the provider name the lookup queries
// by (an identity saved under another name would never be found again). The provider's access
// and refresh tokens are never stored: sign-in needs them only for the profile call, and the
// privacy policy (section 5A) says they are not kept.
func (s *Service) createIdentity(ctx context.Context, userID uuid.UUID, sp *SocialProfile) error {
	if _, err := s.entClient.UserIdentity.Create().
		SetUserID(userID).
		SetProvider(sp.Provider).
		SetProviderSubject(sp.Subject).
		SetProviderEmail(identityEmail(sp)).
		SetEmailVerified(sp.EmailTrusted).
		SetTokenExpiry(tokenExpiry(sp.Token)).
		SetScope(scopeFromToken(sp.Token)).
		SetProfile(sp.Profile).
		Save(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return ErrSocialIdentityLinkedElsewhere
		}
		return fmt.Errorf("create user identity: %w", err)
	}
	return nil
}

// updateIdentity refreshes the identity after a sign-in and clears any provider tokens left from
// before they stopped being stored.
func (s *Service) updateIdentity(ctx context.Context, identityID uuid.UUID, sp *SocialProfile) error {
	if err := s.entClient.UserIdentity.UpdateOneID(identityID).
		SetProviderEmail(identityEmail(sp)).
		SetEmailVerified(sp.EmailTrusted).
		SetTokenExpiry(tokenExpiry(sp.Token)).
		SetScope(scopeFromToken(sp.Token)).
		SetProfile(sp.Profile).
		ClearAccessToken().
		ClearRefreshToken().
		Exec(ctx); err != nil {
		return fmt.Errorf("update user identity: %w", err)
	}
	return nil
}

// linkSocialIdentity adds the provider account to userID. A provider account already linked to
// someone else is refused; linking it again to the same person only refreshes it.
func (s *Service) linkSocialIdentity(ctx context.Context, userID uuid.UUID, sp *SocialProfile, ip, ua string) error {
	userEntity, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSocialLinkSessionMismatch
		}
		return fmt.Errorf("load user: %w", err)
	}
	identity, err := s.entClient.UserIdentity.Query().
		Where(useridentity.ProviderEQ(sp.Provider), useridentity.ProviderSubjectEQ(sp.Subject)).
		Only(ctx)
	switch {
	case err == nil && identity.UserID != userID:
		s.auditSecurityEvent(ctx, userEntity, nil, "auth.identity.link_refused",
			map[string]any{"provider": sp.Provider, "reason": "linked_to_another_user"}, ip, ua)
		return ErrSocialIdentityLinkedElsewhere
	case err == nil:
		return s.updateIdentity(ctx, identity.ID, sp)
	case !ent.IsNotFound(err):
		return fmt.Errorf("query user identity: %w", err)
	}
	if err := s.createIdentity(ctx, userID, sp); err != nil {
		return err
	}
	s.auditSecurityEvent(ctx, userEntity, nil, "auth.identity.linked", map[string]any{"provider": sp.Provider}, ip, ua)
	return nil
}

// SocialIdentities lists the provider accounts linked to the user, and whether the account also
// has a password (the UI shows which methods can be unlinked).
func (s *Service) SocialIdentities(ctx context.Context, userID uuid.UUID) ([]*ent.UserIdentity, bool, error) {
	userEntity, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("load user: %w", err)
	}
	rows, err := s.entClient.UserIdentity.Query().
		Where(useridentity.UserIDEQ(userID)).
		Order(ent.Asc(useridentity.FieldLinkedAt)).
		All(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("list user identities: %w", err)
	}
	return rows, userEntity.PasswordHash != "", nil
}

// UnlinkSocialIdentity removes a linked provider account, unless it is the account's only way to
// sign in (no password and no other linked provider).
func (s *Service) UnlinkSocialIdentity(ctx context.Context, userID, identityID uuid.UUID, ip, ua string) error {
	identity, err := s.entClient.UserIdentity.Query().
		Where(useridentity.IDEQ(identityID), useridentity.UserIDEQ(userID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrSocialIdentityNotFound
		}
		return fmt.Errorf("load user identity: %w", err)
	}
	rows, hasPassword, err := s.SocialIdentities(ctx, userID)
	if err != nil {
		return err
	}
	if !hasPassword && len(rows) <= 1 {
		return ErrLastSignInMethod
	}
	if err := s.entClient.UserIdentity.DeleteOneID(identity.ID).Exec(ctx); err != nil {
		return fmt.Errorf("delete user identity: %w", err)
	}
	if userEntity, err := s.entClient.User.Get(ctx, userID); err == nil {
		s.auditSecurityEvent(ctx, userEntity, nil, "auth.identity.unlinked", map[string]any{"provider": identity.Provider}, ip, ua)
	}
	return nil
}
