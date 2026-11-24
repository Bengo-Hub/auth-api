package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/bengobox/auth-api/internal/oauth/state"
	githubprovider "github.com/bengobox/auth-api/internal/providers/github"
	googleprovider "github.com/bengobox/auth-api/internal/providers/google"
	microsoftprovider "github.com/bengobox/auth-api/internal/providers/microsoft"
	tiktokprovider "github.com/bengobox/auth-api/internal/providers/tiktok"
)

// Social sign-in runs one code path for every provider. Each provider only has to say who the
// person is (SocialProfile); finding or creating the account, the membership policy, MFA, the
// session and account linking are shared.

// socialLinkFlow is the OAuth state flow of "link this provider to my account". It is only ever
// written by StartSocialLink, for the signed-in person, never by the public start endpoints.
const socialLinkFlow = "link"

// SocialProfile is the provider-neutral result of a provider round trip.
type SocialProfile struct {
	Provider string
	Subject  string
	// Email is what the provider reported, possibly empty (TikTok shares none).
	Email string
	// EmailTrusted is true only when the provider proves the person owns Email: Google's
	// email_verified, GitHub's primary verified address, Microsoft's xms_edov claim. Only a trusted
	// email may match an existing account.
	EmailTrusted bool
	Name         string
	Picture      string
	// Profile is stored on the identity row.
	Profile map[string]any
	Token   *oauth2.Token
}

// socialProvider is what the shared flow needs from a provider.
type socialProvider interface {
	AuthCodeURL(ctx context.Context, state string) (string, error)
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	SocialProfile(ctx context.Context, token *oauth2.Token) (*SocialProfile, error)
}

// The provider packages, as the sign-in flow sees them (fakes in tests).
type googleOAuth interface {
	AuthCodeURL(ctx context.Context, state string) (string, error)
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchProfile(ctx context.Context, token *oauth2.Token) (*googleprovider.Profile, error)
}

type githubOAuth interface {
	AuthCodeURL(ctx context.Context, state string) (string, error)
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchProfile(ctx context.Context, token *oauth2.Token) (*githubprovider.Profile, error)
}

type microsoftOAuth interface {
	AuthCodeURL(ctx context.Context, state string) (string, error)
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchProfile(ctx context.Context, token *oauth2.Token) (*microsoftprovider.Profile, error)
}

type googleAdapter struct{ googleOAuth }

func (a googleAdapter) SocialProfile(ctx context.Context, tok *oauth2.Token) (*SocialProfile, error) {
	p, err := a.FetchProfile(ctx, tok)
	if err != nil {
		return nil, err
	}
	return googleSocialProfile(p, tok), nil
}

type githubAdapter struct{ githubOAuth }

func (a githubAdapter) SocialProfile(ctx context.Context, tok *oauth2.Token) (*SocialProfile, error) {
	p, err := a.FetchProfile(ctx, tok)
	if err != nil {
		return nil, err
	}
	return githubSocialProfile(p, tok), nil
}

type microsoftAdapter struct{ microsoftOAuth }

func (a microsoftAdapter) SocialProfile(ctx context.Context, tok *oauth2.Token) (*SocialProfile, error) {
	p, err := a.FetchProfile(ctx, tok)
	if err != nil {
		return nil, err
	}
	return microsoftSocialProfile(p, tok), nil
}

type tiktokAdapter struct{ tiktokOAuth }

func (a tiktokAdapter) SocialProfile(ctx context.Context, tok *oauth2.Token) (*SocialProfile, error) {
	p, err := a.FetchProfile(ctx, tok)
	if err != nil {
		return nil, err
	}
	return tiktokSocialProfile(p, tok), nil
}

// googleSocialProfile trusts the email only when Google says it is verified.
func googleSocialProfile(p *googleprovider.Profile, tok *oauth2.Token) *SocialProfile {
	return &SocialProfile{
		Provider:     googleProviderName,
		Subject:      p.Subject,
		Email:        p.Email,
		EmailTrusted: p.EmailVerified && p.Email != "",
		Name:         p.Name,
		Picture:      p.Picture,
		Profile:      map[string]any{"name": p.Name, "picture": p.Picture, "locale": p.Locale},
		Token:        tok,
	}
}

// githubSocialProfile trusts only the primary verified address from /user/emails. The public
// profile email is kept on the identity but never matches an account.
func githubSocialProfile(p *githubprovider.Profile, tok *oauth2.Token) *SocialProfile {
	sp := &SocialProfile{
		Provider: githubProviderName,
		Email:    p.Email,
		Name:     p.Name,
		Picture:  p.Avatar,
		Profile:  map[string]any{"name": p.Name, "picture": p.Avatar, "login": p.Login},
		Token:    tok,
	}
	if p.ID != 0 {
		sp.Subject = fmt.Sprintf("%d", p.ID)
	}
	if sp.Name == "" {
		sp.Name = p.Login
	}
	if p.VerifiedEmail != "" {
		sp.Email, sp.EmailTrusted = p.VerifiedEmail, true
	}
	return sp
}

// microsoftSocialProfile trusts the email only with the xms_edov claim. Graph's mail and
// userPrincipalName can be set to any address by the person's own Entra admin.
func microsoftSocialProfile(p *microsoftprovider.Profile, tok *oauth2.Token) *SocialProfile {
	sp := &SocialProfile{
		Provider: microsoftProviderName,
		Subject:  p.ID,
		Email:    p.Mail,
		Name:     p.DisplayName,
		Profile:  map[string]any{"name": p.DisplayName},
		Token:    tok,
	}
	if sp.Email == "" {
		sp.Email = p.UserPrincipalName
	}
	if verified, ok := microsoftprovider.VerifiedEmail(tok); ok {
		sp.Email, sp.EmailTrusted = verified, true
	}
	return sp
}

// tiktokSocialProfile has no email: the account is found by open_id only.
func tiktokSocialProfile(p *tiktokprovider.Profile, tok *oauth2.Token) *SocialProfile {
	return &SocialProfile{
		Provider: tiktokProviderName,
		Subject:  p.OpenID,
		Name:     p.DisplayName,
		Picture:  p.AvatarURL,
		Profile:  tiktokIdentityProfile(p),
		Token:    tok,
	}
}

// socialProvider returns the enabled provider by name, or nil.
func (s *Service) socialProvider(name string) socialProvider {
	switch name {
	case googleProviderName:
		if s.google != nil {
			return googleAdapter{s.google}
		}
	case githubProviderName:
		if s.github != nil {
			return githubAdapter{s.github}
		}
	case microsoftProviderName:
		if s.microsoft != nil {
			return microsoftAdapter{s.microsoft}
		}
	case tiktokProviderName:
		if s.tiktok != nil {
			return tiktokAdapter{s.tiktok}
		}
	}
	return nil
}

// StartGoogleOAuth builds the Google authorization URL.
func (s *Service) StartGoogleOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	return s.startSocialOAuth(ctx, googleProviderName, in, uuid.Nil)
}

// StartGitHubOAuth builds the GitHub authorization URL.
func (s *Service) StartGitHubOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	return s.startSocialOAuth(ctx, githubProviderName, in, uuid.Nil)
}

// StartMicrosoftOAuth builds the Microsoft authorization URL.
func (s *Service) StartMicrosoftOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	return s.startSocialOAuth(ctx, microsoftProviderName, in, uuid.Nil)
}

// StartTikTokOAuth builds the TikTok authorization URL.
func (s *Service) StartTikTokOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	return s.startSocialOAuth(ctx, tiktokProviderName, in, uuid.Nil)
}

// CompleteGoogleOAuth finishes the Google callback.
func (s *Service) CompleteGoogleOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	return s.completeSocialOAuth(ctx, googleProviderName, in)
}

// CompleteGitHubOAuth finishes the GitHub callback.
func (s *Service) CompleteGitHubOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	return s.completeSocialOAuth(ctx, githubProviderName, in)
}

// CompleteMicrosoftOAuth finishes the Microsoft callback.
func (s *Service) CompleteMicrosoftOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	return s.completeSocialOAuth(ctx, microsoftProviderName, in)
}

// CompleteTikTokOAuth finishes the TikTok callback.
func (s *Service) CompleteTikTokOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	return s.completeSocialOAuth(ctx, tiktokProviderName, in)
}

// StartSocialLink begins linking a provider to the signed-in person's account. The person's id is
// signed into the state and checked again at the callback against the browser's session.
func (s *Service) StartSocialLink(ctx context.Context, provider string, userID uuid.UUID, in OAuthStartInput) (string, error) {
	if userID == uuid.Nil {
		return "", ErrSocialLinkSessionMismatch
	}
	in.Flow = socialLinkFlow
	return s.startSocialOAuth(ctx, strings.ToLower(provider), in, userID)
}

// startSocialOAuth signs the state and builds the provider's authorization URL. linkUserID is set
// only for the link flow.
func (s *Service) startSocialOAuth(ctx context.Context, provider string, in OAuthStartInput, linkUserID uuid.UUID) (string, error) {
	p := s.socialProvider(provider)
	if p == nil {
		return "", ErrProviderNotEnabled
	}
	flow := defaultFlow(in.Flow)
	payload := state.Payload{
		ClientID:    in.ClientID,
		Portal:      s.isPortalOrigin(in.Origin),
		Flow:        flow,
		RedirectURI: in.RedirectURI,
		Nonce:       randomNonce(),
		ReturnTo:    SafeOAuthReturnTo(in.ReturnTo, s.cfg.Token.Issuer, s.trustedHosts(ctx)...),
	}
	if flow == socialLinkFlow {
		// A public start can never ask for the link flow: it has no signed-in person.
		if linkUserID == uuid.Nil {
			return "", ErrOAuthStateInvalid
		}
		payload.UserID = linkUserID.String()
	} else {
		tenantEntity, err := s.resolveOAuthStartTenant(ctx, in.TenantSlug, in.ClientID)
		if err != nil {
			return "", err
		}
		payload.TenantSlug = tenantEntity.Slug
		payload.Defaulted = strings.TrimSpace(in.TenantSlug) == ""
	}
	stateToken, err := state.Encode(s.cfg.Security.OAuthStateSecret, payload, oauthStateTTL)
	if err != nil {
		return "", fmt.Errorf("encode oauth state: %w", err)
	}
	authURL, err := p.AuthCodeURL(ctx, stateToken)
	if err != nil {
		// A disabled or unreadable provider config is an unavailable provider, not a server fault.
		return "", fmt.Errorf("%w: %v", ErrProviderNotEnabled, err)
	}
	return authURL, nil
}

// completeSocialOAuth handles every provider callback: sign-in, or linking when the state says so.
func (s *Service) completeSocialOAuth(ctx context.Context, provider string, in OAuthCallbackInput) (*AuthResult, error) {
	p := s.socialProvider(provider)
	if p == nil {
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
	if payload.Flow == socialLinkFlow {
		return s.completeSocialLink(ctx, provider, p, payload, in)
	}

	tenantEntity, err := s.GetTenantBySlug(ctx, payload.TenantSlug)
	if err != nil {
		return nil, err
	}
	sp, err := fetchSocialProfile(ctx, p, in.Code)
	if err != nil {
		return nil, err
	}
	userEntity, err := s.resolveSocialUser(ctx, tenantEntity, s.oauthJoinRole(ctx, payload.ClientID), sp)
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
		// No session yet: the person confirms the authenticator code first.
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
		"method":      provider,
		"ip_address":  in.IPAddress,
	})
	return result, nil
}

// completeSocialLink adds the provider identity to the person named in the state. The browser's
// own session must be that same person: a state lifted from someone else's browser is useless.
func (s *Service) completeSocialLink(ctx context.Context, provider string, p socialProvider, payload *state.Payload, in OAuthCallbackInput) (*AuthResult, error) {
	fail := func(err error) (*AuthResult, error) {
		return nil, &SocialLinkError{Provider: provider, Err: err}
	}
	linkUserID, err := uuid.Parse(payload.UserID)
	if err != nil || linkUserID == uuid.Nil || in.SessionUserID != linkUserID {
		return fail(ErrSocialLinkSessionMismatch)
	}
	sp, err := fetchSocialProfile(ctx, p, in.Code)
	if err != nil {
		return fail(err)
	}
	if err := s.linkSocialIdentity(ctx, linkUserID, sp, in.IPAddress, in.UserAgent); err != nil {
		return fail(err)
	}
	return &AuthResult{LinkedProvider: provider, ReturnTo: payload.ReturnTo}, nil
}

func fetchSocialProfile(ctx context.Context, p socialProvider, code string) (*SocialProfile, error) {
	tok, err := p.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	sp, err := p.SocialProfile(ctx, tok)
	if err != nil {
		return nil, err
	}
	sp.Subject = strings.TrimSpace(sp.Subject)
	if sp.Subject == "" {
		return nil, fmt.Errorf("%s profile has no account id", sp.Provider)
	}
	sp.Email = normalizeEmail(sp.Email)
	if sp.Email == "" {
		sp.EmailTrusted = false
	}
	return sp, nil
}
