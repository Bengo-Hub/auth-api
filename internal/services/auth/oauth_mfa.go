package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/oauth/state"
)

// socialMFAChallengeTTL bounds how long a person has to type the code after the provider step.
const socialMFAChallengeTTL = 5 * time.Minute

// ErrMFACodeInvalid is returned when the authenticator code does not match.
var ErrMFACodeInvalid = errors.New("invalid authenticator code")

// SocialMFAInput is the second step of a social sign-in for an account with an authenticator app.
type SocialMFAInput struct {
	Challenge string
	Code      string
	IPAddress string
	UserAgent string
}

// socialMFARequired reports whether the account owes an authenticator code. A lookup error fails
// closed (the code is asked for) rather than skipping a second factor.
func (s *Service) socialMFARequired(ctx context.Context, userID uuid.UUID) bool {
	on, err := s.IsMFAEnabled(ctx, userID)
	return err != nil || on
}

// socialMFAResult is what a provider callback returns instead of a session when the account has
// MFA: no tokens, only a short-lived signed challenge the browser exchanges with the code.
func (s *Service) socialMFAResult(userEntity *ent.User, tenantEntity *ent.Tenant, payload *state.Payload) (*AuthResult, error) {
	challenge, err := state.Encode(s.cfg.Security.OAuthStateSecret, state.Payload{
		TenantSlug: tenantEntity.Slug,
		ClientID:   payload.ClientID,
		Flow:       defaultFlow(payload.Flow),
		Nonce:      randomNonce(),
		ReturnTo:   payload.ReturnTo,
		Purpose:    state.PurposeSocialMFA,
		UserID:     userEntity.ID.String(),
	}, socialMFAChallengeTTL)
	if err != nil {
		return nil, fmt.Errorf("encode social mfa challenge: %w", err)
	}
	return &AuthResult{
		User:         userEntity,
		Tenant:       tenantEntity,
		MFAChallenge: challenge,
		ReturnTo:     payload.ReturnTo,
	}, nil
}

func (s *Service) decodeSocialMFAChallenge(challenge string) (*state.Payload, error) {
	payload, err := state.Decode(s.cfg.Security.OAuthStateSecret, challenge)
	if err != nil || payload.Purpose != state.PurposeSocialMFA || payload.UserID == "" {
		return nil, ErrOAuthStateInvalid
	}
	return payload, nil
}

// SocialMFAChallengeNonce validates a challenge and returns its nonce and lifetime, which the handler
// uses to limit attempts and stop a challenge being used twice.
func (s *Service) SocialMFAChallengeNonce(challenge string) (string, time.Duration, error) {
	payload, err := s.decodeSocialMFAChallenge(challenge)
	if err != nil {
		return "", 0, err
	}
	return payload.Nonce, socialMFAChallengeTTL, nil
}

// CompleteSocialMFA finishes a social sign-in: the provider step already proved who the person is, and
// here they prove the authenticator code before any session exists.
func (s *Service) CompleteSocialMFA(ctx context.Context, in SocialMFAInput) (*AuthResult, error) {
	payload, err := s.decodeSocialMFAChallenge(in.Challenge)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		return nil, ErrOAuthStateInvalid
	}
	userEntity, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		return nil, ErrOAuthStateInvalid
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, payload.TenantSlug)
	if err != nil {
		return nil, err
	}
	// The same rules as the provider step, re-checked now: roles may have changed in the meantime.
	if s.isPlatformStaffUser(ctx, userEntity.ID) {
		return nil, ErrSocialSignInNotAllowed
	}
	member, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(userEntity.ID), tenantmembership.TenantID(tenantEntity.ID)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("check tenant membership: %w", err)
	}
	if !member {
		return nil, ErrTenantMembershipRequired
	}

	rec, err := s.entClient.MFATOTPSecret.Query().
		Where(mfatotpsecret.UserID(userEntity.ID), mfatotpsecret.EnabledAtNotNil()).
		Only(ctx)
	if err != nil {
		// MFA was turned off between the two steps, or the lookup failed: never fall through to a session.
		return nil, ErrMFACodeInvalid
	}
	code := strings.TrimSpace(in.Code)
	if code == "" || !totp.Validate(code, rec.Secret) {
		s.auditSecurityEvent(ctx, userEntity, tenantEntity, "auth.oauth.mfa.failed", map[string]any{"reason": "bad_code"}, in.IPAddress, in.UserAgent)
		return nil, ErrMFACodeInvalid
	}

	result, err := s.issueSession(ctx, issueSessionInput{
		User:      userEntity,
		Tenant:    tenantEntity,
		ClientID:  payload.ClientID,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		Scopes:    s.cfg.Token.DefaultScopes,
	})
	if err != nil {
		return nil, err
	}
	result.ReturnTo = payload.ReturnTo
	// A successful sign-in is not audited: the session row records it, and the audit log is kept for
	// security events (refusals, failed codes, privilege changes).
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "login", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"method":      "social_mfa",
		"ip_address":  in.IPAddress,
	})
	return result, nil
}

// auditSecurityEvent records an event worth an investigator's time. Routine activity (a successful
// sign-in, an OAuth start, a token refresh) is deliberately not written here.
func (s *Service) auditSecurityEvent(ctx context.Context, userEntity *ent.User, tenantEntity *ent.Tenant, action string, extra map[string]any, ip, ua string) {
	entry := audit.Entry{
		UserID:     &userEntity.ID,
		Action:     action,
		Resource:   "user",
		ResourceID: userEntity.ID.String(),
		IPAddress:  ip,
		UserAgent:  ua,
		Context:    extra,
	}
	if tenantEntity != nil {
		entry.TenantID = &tenantEntity.ID
	}
	s.auditor.Record(ctx, entry)
	s.logger.Warn("security event", zap.String("action", action), zap.String("user_id", userEntity.ID.String()))
}
