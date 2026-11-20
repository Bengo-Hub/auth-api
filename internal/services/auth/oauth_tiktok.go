package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
	"github.com/bengobox/auth-api/internal/oauth/state"
	tiktokprovider "github.com/bengobox/auth-api/internal/providers/tiktok"
)

// tiktokOAuth is what the sign-in flow needs from the TikTok provider (a fake in tests).
type tiktokOAuth interface {
	AuthCodeURL(ctx context.Context, state string) (string, error)
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchProfile(ctx context.Context, token *oauth2.Token) (*tiktokprovider.Profile, error)
}

// TikTokPlaceholderEmail mints the synthetic address for an account created by TikTok sign-in.
// TikTok shares no email, so the account gets a ".local" placeholder like a phone-only account,
// and the verify-email dialog asks the person for a real address (IsPlaceholderEmail).
func TikTokPlaceholderEmail(openID string) string {
	sum := sha256.Sum256([]byte(openID))
	return "tiktok-" + hex.EncodeToString(sum[:8]) + "@placeholder.local"
}

// StartTikTokOAuth builds the TikTok authorization URL. Same signed state as every provider.
func (s *Service) StartTikTokOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	if s.tiktok == nil {
		return "", ErrProviderNotEnabled
	}
	tenantEntity, err := s.resolveOAuthStartTenant(ctx, in.TenantSlug)
	if err != nil {
		return "", err
	}
	payload := state.Payload{
		TenantSlug:  tenantEntity.Slug,
		ClientID:    in.ClientID,
		Portal:      s.isPortalOrigin(in.Origin),
		Flow:        defaultFlow(in.Flow),
		RedirectURI: in.RedirectURI,
		Nonce:       randomNonce(),
		ReturnTo:    SafeOAuthReturnTo(in.ReturnTo, s.cfg.Token.Issuer, s.trustedHosts(ctx)...),
		Defaulted:   strings.TrimSpace(in.TenantSlug) == "",
	}
	stateToken, err := state.Encode(s.cfg.Security.OAuthStateSecret, payload, oauthStateTTL)
	if err != nil {
		return "", fmt.Errorf("encode oauth state: %w", err)
	}
	authURL, err := s.tiktok.AuthCodeURL(ctx, stateToken)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrProviderNotEnabled, err)
	}
	return authURL, nil
}

// CompleteTikTokOAuth handles the TikTok callback: the same membership, 2FA and session rules as
// Google, GitHub and Microsoft, with the account found by TikTok open_id instead of email.
func (s *Service) CompleteTikTokOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	if s.tiktok == nil {
		return nil, ErrProviderNotEnabled
	}
	if in.Code == "" || in.State == "" {
		return nil, ErrOAuthStateInvalid
	}
	payload, err := state.Decode(s.cfg.Security.OAuthStateSecret, in.State)
	if err != nil || payload.Purpose != "" {
		// A social MFA challenge is signed with the same key; it must never pass as a provider state.
		return nil, ErrOAuthStateInvalid
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, payload.TenantSlug)
	if err != nil {
		return nil, err
	}
	tokenResp, err := s.tiktok.Exchange(ctx, in.Code)
	if err != nil {
		return nil, err
	}
	profile, err := s.tiktok.FetchProfile(ctx, tokenResp)
	if err != nil {
		return nil, err
	}
	userEntity, err := s.resolveUserFromTikTokProfile(ctx, tenantEntity, s.oauthJoinRole(ctx, payload.ClientID), profile, tokenResp)
	if errors.Is(err, ErrTenantMembershipRequired) && payload.Defaulted && userEntity != nil {
		// No organisation was named: sign the person in to their own tenant, not the platform's.
		if home := s.userHomeTenant(ctx, userEntity); home != nil {
			tenantEntity, err = home, nil
		}
	}
	if err != nil {
		return nil, err
	}

	if s.socialMFARequired(ctx, userEntity.ID) {
		return s.socialMFAResult(userEntity, tenantEntity, payload)
	}

	result, err := s.issueSession(ctx, issueSessionInput{
		User:      userEntity,
		Tenant:    tenantEntity,
		ClientID:  payload.ClientID,
		Portal:    payload.Portal,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		Scopes:    s.cfg.Token.DefaultScopes,
		AMR:       []string{AMRFederated},
	})
	if err != nil {
		return nil, err
	}
	result.ReturnTo = payload.ReturnTo

	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "login", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"method":      tiktokProviderName,
		"ip_address":  in.IPAddress,
	})
	return result, nil
}

// tiktokIdentityProfile is the identity row's profile. union_id is kept so a second TikTok app
// of the same developer can be matched to the same person later.
func tiktokIdentityProfile(p *tiktokprovider.Profile) map[string]any {
	return map[string]any{
		"name":     p.DisplayName,
		"picture":  p.AvatarURL,
		"union_id": p.UnionID,
	}
}

// resolveUserFromTikTokProfile finds the account linked to this TikTok open_id, or creates one.
// There is no email to match an existing account by, so a person who first signs in with TikTok
// gets a new account with a placeholder address; the same social sign-up rules decide whether it
// may join the tenant (ensureMembership). A refused sign-up leaves no account behind.
func (s *Service) resolveUserFromTikTokProfile(ctx context.Context, tenantEntity *ent.Tenant, joinRole string, profile *tiktokprovider.Profile, token *oauth2.Token) (*ent.User, error) {
	if profile == nil || strings.TrimSpace(profile.OpenID) == "" {
		return nil, errors.New("tiktok open_id not available")
	}
	sub := profile.OpenID
	identity, err := s.entClient.UserIdentity.Query().
		Where(useridentity.ProviderEQ(tiktokProviderName), useridentity.ProviderSubjectEQ(sub)).
		WithUser().
		Only(ctx)
	if err == nil {
		userEntity := identity.Edges.User
		if !s.isDomainAllowed(userEntity.Email) {
			return nil, ErrEmailDomainNotAllowed
		}
		if err := s.ensureMembership(ctx, userEntity, tenantEntity, joinRole); err != nil {
			return userEntity, err
		}
		if err := s.entClient.UserIdentity.UpdateOneID(identity.ID).
			SetTokenExpiry(tokenExpiry(token)).
			SetScope(scopeFromToken(token)).
			SetProfile(tiktokIdentityProfile(profile)).
			ClearAccessToken().
			ClearRefreshToken().
			Exec(ctx); err != nil {
			return nil, fmt.Errorf("update tiktok identity: %w", err)
		}
		if userEntity.PrimaryTenantID == "" {
			if err := s.entClient.User.UpdateOneID(userEntity.ID).
				SetPrimaryTenantID(tenantEntity.ID.String()).
				Exec(ctx); err != nil {
				s.logger.Warn("failed to set primary tenant from oauth", zap.Error(err))
			}
		}
		return userEntity, nil
	}
	if !ent.IsNotFound(err) {
		return nil, fmt.Errorf("query user identity: %w", err)
	}

	email := TikTokPlaceholderEmail(sub)
	if !s.isDomainAllowed(email) {
		// Sign-in is locked to named email domains; a placeholder address never qualifies.
		return nil, ErrEmailDomainNotAllowed
	}
	if taken, err := s.entClient.User.Query().Where(user.EmailEQ(email)).Exist(ctx); err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	} else if taken {
		email = strings.TrimSuffix(email, "@placeholder.local") + "-" + uuid.NewString()[:8] + "@placeholder.local"
	}
	profileMap := map[string]any{"signup_method": tiktokProviderName}
	if name := strings.TrimSpace(profile.DisplayName); name != "" {
		profileMap["name"] = name
	}
	if profile.AvatarURL != "" {
		profileMap["picture"] = profile.AvatarURL
	}
	userEntity, err := s.entClient.User.Create().
		SetEmail(email).
		SetStatus(UserStatusActive).
		SetPrimaryTenantID(tenantEntity.ID.String()).
		SetProfile(profileMap).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create user from tiktok profile: %w", err)
	}
	if err := s.ensureMembership(ctx, userEntity, tenantEntity, joinRole); err != nil {
		if delErr := s.entClient.User.DeleteOneID(userEntity.ID).Exec(ctx); delErr != nil {
			s.logger.Warn("tiktok sign-up: could not remove refused account", zap.Error(delErr))
		}
		return nil, err
	}
	if _, err := s.entClient.UserIdentity.Create().
		SetUserID(userEntity.ID).
		SetProvider(tiktokProviderName).
		SetProviderSubject(sub).
		SetProviderEmail(email).
		SetTokenExpiry(tokenExpiry(token)).
		SetScope(scopeFromToken(token)).
		SetProfile(tiktokIdentityProfile(profile)).
		Save(ctx); err != nil {
		return nil, fmt.Errorf("create user identity: %w", err)
	}
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"full_name":   profileStr(userEntity.Profile, "name"),
		"phone":       profileStr(userEntity.Profile, "phone"),
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"roles":       []string{joinRole},
		"method":      tiktokProviderName,
	})
	return userEntity, nil
}
