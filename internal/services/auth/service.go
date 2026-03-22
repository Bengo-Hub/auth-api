package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/audit"
	"github.com/bengobox/auth-api/internal/clients/subscription"
	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/bengobox/auth-api/internal/ent/passwordresettoken"
	"github.com/bengobox/auth-api/internal/ent/rolepermission"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/user"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
	"github.com/bengobox/auth-api/internal/oauth/state"
	"github.com/bengobox/auth-api/internal/password"
	githubprovider "github.com/bengobox/auth-api/internal/providers/github"
	googleprovider "github.com/bengobox/auth-api/internal/providers/google"
	microsoftprovider "github.com/bengobox/auth-api/internal/providers/microsoft"
	"github.com/bengobox/auth-api/internal/services/integrations"
	"github.com/bengobox/auth-api/internal/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var (
	// ErrInvalidCredentials returned when login fails.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrPasswordTooWeak returned when password fails policy validation.
	ErrPasswordTooWeak = errors.New("password too weak")
	// ErrTenantNotFound returned when tenant slug missing.
	ErrTenantNotFound = errors.New("tenant not found")
	// ErrPasswordResetTokenInvalid indicates invalid/expired token.
	ErrPasswordResetTokenInvalid = errors.New("password reset token invalid or expired")
	// ErrEmailAlreadyExists indicates duplicate registration.
	ErrEmailAlreadyExists = errors.New("user with email already exists")
	// ErrProviderNotEnabled indicates the requested OAuth provider is disabled.
	ErrProviderNotEnabled = errors.New("oauth provider not enabled")
	// ErrOAuthStateInvalid indicates malformed state payload.
	ErrOAuthStateInvalid = errors.New("oauth state invalid")
	// ErrEmailNotVerified indicates provider did not verify the email address.
	ErrEmailNotVerified = errors.New("provider email not verified")
	// ErrEmailDomainNotAllowed indicates the email domain is not in the allowed list.
	ErrEmailDomainNotAllowed = errors.New("email domain not allowed")
	// ErrTenantInactive indicates the requested tenant is not active.
	ErrTenantInactive = errors.New("tenant is not active")
)

// TenantMismatchError is returned when a user's credentials are valid but they
// are not a member of the requested tenant. It carries the user's actual tenants
// so the frontend can suggest switching.
type TenantMismatchError struct {
	RequestedSlug string
	UserTenants   []TenantInfo
}

// TenantInfo is a minimal tenant descriptor returned in mismatch errors.
type TenantInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (e *TenantMismatchError) Error() string {
	return "user is not a member of the requested tenant"
}

const (
	oauthStateTTL         = 10 * time.Minute // 10 minutes
	googleProviderName    = "google"
	githubProviderName    = "github"
	microsoftProviderName = "microsoft"
)

// Service encapsulates core authentication flows.
type Service struct {
	entClient      *ent.Client
	tokenSvc       *token.Service
	hasher         *password.Hasher
	cfg            *config.Config
	auditor        *audit.Logger
	logger         *zap.Logger
	google         *googleprovider.Provider
	revoker        JTIRevoker
	github         *githubprovider.Provider
	microsoft      *microsoftprovider.Provider
	subscriptionCl *subscription.Client
	integrations   *integrations.Service
}

// Dependencies aggregates constructor inputs.
type Dependencies struct {
	EntClient          *ent.Client
	TokenSvc           *token.Service
	Hasher             *password.Hasher
	Config             *config.Config
	Auditor            *audit.Logger
	Logger             *zap.Logger
	Google             *googleprovider.Provider
	Revoker            JTIRevoker
	GitHub             *githubprovider.Provider
	Microsoft          *microsoftprovider.Provider
	SubscriptionClient *subscription.Client
	Integrations       *integrations.Service
}

// New initialises the auth service.
func New(deps Dependencies) *Service {
	return &Service{
		entClient:      deps.EntClient,
		tokenSvc:       deps.TokenSvc,
		hasher:         deps.Hasher,
		cfg:            deps.Config,
		auditor:        deps.Auditor,
		logger:         deps.Logger,
		google:         deps.Google,
		revoker:        deps.Revoker,
		github:         deps.GitHub,
		microsoft:      deps.Microsoft,
		subscriptionCl: deps.SubscriptionClient,
		integrations:   deps.Integrations,
	}
}

// JTIRevoker abstracts a revocation store.
type JTIRevoker interface {
	Revoke(ctx context.Context, jti string, ttl time.Duration) error
}

// NewOrgInput carries new-organisation details when a user creates a new tenant during signup.
type NewOrgInput struct {
	Name         string
	Slug         string
	UseCase      string   // Legacy single value (kept for backward compat)
	UseCases     []string // Multi-select use cases
	HQBranchName string
	Metadata     map[string]any
}

// RegisterInput captures registration payload.
type RegisterInput struct {
	Email      string
	Password   string
	TenantSlug string
	Profile    map[string]any
	IPAddress  string
	UserAgent  string
	ClientID   string
	// SelectedPlan is the subscription plan code chosen by the user in the signup wizard.
	// Required for new org creation ("create_new") to bootstrap the tenant subscription.
	// Accepted values: "STARTER" | "GROWTH" | "PROFESSIONAL" (or any valid plan code).
	SelectedPlan string
	// OrgAction: "join_existing" (default) or "create_new".
	// When "create_new", NewOrg must be non-nil and the registering user
	// is granted the "admin" role for the newly created organisation.
	OrgAction string
	NewOrg    *NewOrgInput
	// Role is an optional role hint for the initial TenantMembership.
	// Used when the registering user was pre-invited with a specific role
	// (e.g. "driver" for fleet invitations). If empty, defaults to "admin"
	// for new orgs or "member" for existing orgs.
	Role string
}

// LoginInput captures login payload.
type LoginInput struct {
	Email      string
	Password   string
	TenantSlug string
	IPAddress  string
	UserAgent  string
	ClientID   string
}

// RefreshInput refresh token payload.
type RefreshInput struct {
	RefreshToken string
	ClientID     string
	IPAddress    string
	UserAgent    string
}

// OAuthStartInput defines payload for initiating external auth.
type OAuthStartInput struct {
	TenantSlug  string
	ClientID    string
	Flow        string
	RedirectURI string
	IPAddress   string
	UserAgent   string
}

// OAuthCallbackInput defines provider callback payload.
type OAuthCallbackInput struct {
	Code      string
	State     string
	IPAddress string
	UserAgent string
}

// PasswordResetRequestInput triggers reset token creation.
type PasswordResetRequestInput struct {
	Email      string
	TenantSlug string
	IPAddress  string
	UserAgent  string
}

// PasswordResetConfirmInput resets password.
type PasswordResetConfirmInput struct {
	Token       string
	NewPassword string
}

// AuthResult returned to caller (login, register, refresh).
// Roles and Permissions are included so frontends can drive RBAC (sidebar, buttons) without a separate /me call.
type AuthResult struct {
	User                  *ent.User
	Tenant                *ent.Tenant
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	SessionID             uuid.UUID
	Roles                 []string // All roles (all tenants) for RBAC; matches GET /me
	Permissions           []string // Canonical permission codes; matches GET /me
}

// GetTenant returns a tenant by ID.
func (s *Service) GetTenant(ctx context.Context, id uuid.UUID) (*ent.Tenant, error) {
	return s.entClient.Tenant.Get(ctx, id)
}

// Register creates a new user and returns session tokens.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*AuthResult, error) {
	if err := s.validatePassword(in.Password); err != nil {
		return nil, err
	}

	var (tenantEntity *ent.Tenant; err error)

	if in.OrgAction == "create_new" && in.NewOrg != nil {
		// Create a brand-new organisation; the registering user becomes its admin.
		meta := coalesceMap(in.NewOrg.Metadata)
		// Determine primary use case: first from UseCases array, fallback to UseCase string
		primaryUseCase := in.NewOrg.UseCase
		if primaryUseCase == "" && len(in.NewOrg.UseCases) > 0 {
			primaryUseCase = in.NewOrg.UseCases[0]
		}
		create := s.entClient.Tenant.Create().
			SetName(in.NewOrg.Name).
			SetSlug(in.NewOrg.Slug).
			SetUseCase(primaryUseCase).
			SetUseCases(in.NewOrg.UseCases).
			SetStatus("active")
		if len(meta) > 0 {
			create = create.SetMetadata(meta)
		}
		tenantEntity, err = create.Save(ctx)
		if err != nil {
			if ent.IsConstraintError(err) {
				// Org already exists — try to look it up so we can join it instead.
				tenantEntity, err = s.entClient.Tenant.Query().
					Where(tenant.SlugEQ(in.NewOrg.Slug)).
					Only(ctx)
				if err != nil {
					return nil, fmt.Errorf("org slug already taken: %w", err)
				}
			} else {
				return nil, fmt.Errorf("create tenant: %w", err)
			}
		}
		// Publish tenant.created event for downstream service sync.
		// Auto-assign STARTER plan with free trial for all new tenants.
		plan := "STARTER"
		if in.SelectedPlan != "" {
			plan = in.SelectedPlan
		}

		if s.subscriptionCl != nil {
			sub, err := s.subscriptionCl.CreateTrialSubscription(ctx, tenantEntity.ID, plan)
			if err != nil {
				s.logger.Warn("failed to provision trial subscription",
					zap.String("tenant_id", tenantEntity.ID.String()),
					zap.String("plan", plan),
					zap.Error(err),
				)
			} else {
				// Update tenant with denormalized subscription data
				_, err = s.entClient.Tenant.UpdateOne(tenantEntity).
					SetSubscriptionID(sub.ID.String()).
					SetSubscriptionPlan(sub.PlanCode).
					SetSubscriptionStatus(sub.Status).
					SetNillableSubscriptionExpiresAt(sub.TrialEndsAt).
					Save(ctx)
				if err != nil {
					s.logger.Warn("failed to update tenant with subscription info",
						zap.String("tenant_id", tenantEntity.ID.String()),
						zap.Error(err),
					)
				}
				// Refresh entity to ensure event has full data
				tenantEntity, _ = s.entClient.Tenant.Get(ctx, tenantEntity.ID)
			}
		}

		s.publishEvent(ctx, tenantEntity.ID, "auth.tenant", tenantEntity.ID, "created", map[string]any{
			"tenant_id":        tenantEntity.ID.String(),
			"name":             tenantEntity.Name,
			"slug":             tenantEntity.Slug,
			"use_case":         tenantEntity.UseCase,
			"subscription_id":  tenantEntity.SubscriptionID,
			"selected_plan":    tenantEntity.SubscriptionPlan,
			"created_by":       in.Email,
		})

		// Initialize Main/HQ branch
		hqName := "Main/HQ"
		if in.NewOrg.HQBranchName != "" {
			hqName = in.NewOrg.HQBranchName
		}
		s.publishEvent(ctx, tenantEntity.ID, "auth.tenant.branch", tenantEntity.ID, "created", map[string]any{
			"tenant_id":  tenantEntity.ID.String(),
			"name":       hqName,
			"is_default": true,
			"use_case":   tenantEntity.UseCase,
		})
	} else {
		tenantEntity, err = s.GetTenantBySlug(ctx, in.TenantSlug)
		if err != nil {
			return nil, err
		}
	}

	hashed, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	email := normalizeEmail(in.Email)
	userEntity, err := s.entClient.User.Create().
		SetEmail(email).
		SetPasswordHash(hashed).
		SetStatus("active").
		SetPrimaryTenantID(tenantEntity.ID.String()).
		SetProfile(coalesceMap(in.Profile)).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	// Assign role: admin when founding a new org, member when joining existing.
	// If a specific role was requested (e.g. "driver" from fleet invitation), use it.
	initialRole := "member"
	if in.Role != "" {
		initialRole = in.Role
	} else if in.OrgAction == "create_new" {
		initialRole = "admin"
	}

	_, err = s.entClient.TenantMembership.Create().
		SetUserID(userEntity.ID).
		SetTenantID(tenantEntity.ID).
		SetRoles([]string{initialRole}).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			s.logger.Warn("tenant membership already exists", zap.String("user_id", userEntity.ID.String()), zap.String("tenant_id", tenantEntity.ID.String()))
		} else {
			return nil, fmt.Errorf("create tenant membership: %w", err)
		}
	}

	s.auditor.Record(ctx, audit.Entry{
		TenantID:   &tenantEntity.ID,
		UserID:     &userEntity.ID,
		Action:     "auth.user.registered",
		Resource:   "user",
		ResourceID: userEntity.ID.String(),
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
		Context: map[string]any{
			"tenant_slug": tenantEntity.Slug,
			"org_action":  in.OrgAction,
			"role":        initialRole,
		},
	})

	// Publish user.created event for downstream service sync
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"full_name":   profileStr(userEntity.Profile, "name"),
		"phone":       profileStr(userEntity.Profile, "phone"),
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"roles":       []string{initialRole},
		"method":      "email",
	})

	return s.issueSession(ctx, issueSessionInput{
		User:      userEntity,
		Tenant:    tenantEntity,
		ClientID:  in.ClientID,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		Scopes:    s.cfg.Token.DefaultScopes,
	})
}

// Login authenticates a user with email/password.
// If tenant_slug is not provided, the tenant is resolved from the user's primary_tenant_id in the DB.
// If primary_tenant_id is not set or the tenant cannot be found, falls back to the user's first active
// TenantMembership record — this allows direct auth-ui login without a service redirect.
func (s *Service) Login(ctx context.Context, in LoginInput) (*AuthResult, error) {
	userEntity, err := s.entClient.User.Query().
		Where(
			user.EmailEQ(normalizeEmail(in.Email)),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("query user: %w", err)
	}

	var tenantEntity *ent.Tenant
	if strings.TrimSpace(in.TenantSlug) != "" {
		tenantEntity, err = s.GetTenantBySlug(ctx, in.TenantSlug)
		if err != nil {
			return nil, err
		}
	} else {
		// Attempt 1: resolve from primary_tenant_id (fastest path).
		if primaryID := strings.TrimSpace(userEntity.PrimaryTenantID); primaryID != "" {
			if primaryTenantUUID, parseErr := uuid.Parse(primaryID); parseErr == nil {
				if t, getErr := s.GetTenant(ctx, primaryTenantUUID); getErr == nil && t.Status == "active" {
					tenantEntity = t
				}
			}
		}

		// Attempt 2: resolve from the user's TenantMembership records when primary_tenant_id
		// is unset, invalid, or points to an inactive/deleted tenant.
		if tenantEntity == nil {
			memberships, mErr := s.entClient.TenantMembership.Query().
				Where(tenantmembership.UserID(userEntity.ID)).
				WithTenant().
				All(ctx)
			if mErr != nil {
				s.logger.Warn("login: failed to resolve tenant from memberships", zap.Error(mErr))
				return nil, ErrInvalidCredentials
			}
			for _, m := range memberships {
				if m.Edges.Tenant != nil && m.Edges.Tenant.Status == "active" {
					tenantEntity = m.Edges.Tenant
					// Back-fill primary_tenant_id so future logins skip this fallback.
					_ = s.entClient.User.UpdateOneID(userEntity.ID).
						SetPrimaryTenantID(tenantEntity.ID.String()).
						Exec(ctx)
					break
				}
			}
		}

		if tenantEntity == nil {
			return nil, ErrTenantNotFound
		}
	}

	// Verify password BEFORE membership check. This ensures we never reveal
	// tenant membership information to someone who doesn't know the password.
	if err := s.hasher.Compare(userEntity.PasswordHash, in.Password); err != nil {
		s.recordLoginAttempt(ctx, tenantEntity.ID, userEntity.ID, in.Email, false, "password_mismatch", in.IPAddress, in.UserAgent)
		return nil, ErrInvalidCredentials
	}

	// Verify membership in the resolved tenant.
	_, err = s.entClient.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userEntity.ID),
			tenantmembership.TenantID(tenantEntity.ID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			// Password was correct but user is not a member of the requested tenant.
			// When a tenant_slug was explicitly provided (e.g. from a service redirect),
			// return the user's actual tenants so the frontend can suggest switching.
			if strings.TrimSpace(in.TenantSlug) != "" {
				memberships, mErr := s.entClient.TenantMembership.Query().
					Where(tenantmembership.UserID(userEntity.ID)).
					WithTenant().
					All(ctx)
				if mErr == nil && len(memberships) > 0 {
					var tenants []TenantInfo
					for _, m := range memberships {
						if m.Edges.Tenant != nil && m.Edges.Tenant.Status == "active" {
							tenants = append(tenants, TenantInfo{
								ID:   m.Edges.Tenant.ID.String(),
								Name: m.Edges.Tenant.Name,
								Slug: m.Edges.Tenant.Slug,
							})
						}
					}
					if len(tenants) > 0 {
						return nil, &TenantMismatchError{
							RequestedSlug: in.TenantSlug,
							UserTenants:   tenants,
						}
					}
				}
			}
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("verify membership: %w", err)
	}

	s.recordLoginAttempt(ctx, tenantEntity.ID, userEntity.ID, in.Email, true, "", in.IPAddress, in.UserAgent)
	s.auditor.Record(ctx, audit.Entry{
		TenantID:   &tenantEntity.ID,
		UserID:     &userEntity.ID,
		Action:     "auth.user.login",
		Resource:   "session",
		ResourceID: userEntity.ID.String(),
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
	})

	// Publish user.login event
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "login", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"full_name":   profileStr(userEntity.Profile, "name"),
		"phone":       profileStr(userEntity.Profile, "phone"),
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"method":      "email",
		"ip_address":  in.IPAddress,
	})

	if err := s.entClient.User.UpdateOneID(userEntity.ID).
		SetLastLoginAt(time.Now().UTC()).
		Exec(ctx); err != nil {
		s.logger.Warn("failed to update last login", zap.Error(err))
	}

	return s.issueSession(ctx, issueSessionInput{
		User:      userEntity,
		Tenant:    tenantEntity,
		ClientID:  in.ClientID,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		Scopes:    s.cfg.Token.DefaultScopes,
	})
}

// Refresh exchanges a refresh token for a new token pair.
func (s *Service) Refresh(ctx context.Context, in RefreshInput) (*AuthResult, error) {
	if in.RefreshToken == "" {
		return nil, ErrInvalidCredentials
	}
	hash := hashToken(in.RefreshToken)

	sessionEntity, err := s.entClient.Session.
		Query().
		Where(
			session.RefreshTokenHashEQ(hash),
			session.StatusEQ("active"),
		).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("query session: %w", err)
	}

	if sessionEntity.ExpiresAt.Before(time.Now()) {
		return nil, ErrInvalidCredentials
	}

	var tenantEntity *ent.Tenant
	if sessionEntity.TenantID != uuid.Nil {
		tenantEntity, err = s.entClient.Tenant.Get(ctx, sessionEntity.TenantID)
		if err != nil {
			return nil, fmt.Errorf("load tenant: %w", err)
		}
	}

	refreshToken := in.RefreshToken
	if s.cfg.Token.RotateRefreshTokens {
		userEdge := sessionEntity.Edges.User
		plain, hashed, err := s.tokenSvc.GenerateRefreshToken()
		if err != nil {
			return nil, fmt.Errorf("generate refresh token: %w", err)
		}
		refreshToken = plain
		sessionEntity, err = sessionEntity.Update().
			SetRefreshTokenHash(hashed).
			SetExpiresAt(time.Now().Add(s.cfg.Token.RefreshTokenTTL)).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("rotate session token: %w", err)
		}
		sessionEntity.Edges.User = userEdge
	}

	return s.issueSessionWithExisting(ctx, sessionEntity, tenantEntity, refreshToken, in.IPAddress, in.UserAgent, s.cfg.Token.DefaultScopes)
}

// StartGoogleOAuth builds the Google OAuth authorization URL.
func (s *Service) StartGoogleOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	if s.google == nil {
		return "", ErrProviderNotEnabled
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, in.TenantSlug)
	if err != nil {
		return "", err
	}

	payload := state.Payload{
		TenantSlug:  tenantEntity.Slug,
		ClientID:    in.ClientID,
		Flow:        defaultFlow(in.Flow),
		RedirectURI: in.RedirectURI,
		Nonce:       randomNonce(),
	}

	stateToken, err := state.Encode(s.cfg.Security.OAuthStateSecret, payload, oauthStateTTL)
	if err != nil {
		return "", fmt.Errorf("encode oauth state: %w", err)
	}

	s.auditor.Record(ctx, audit.Entry{
		TenantID:   &tenantEntity.ID,
		Action:     "auth.oauth.google.start",
		Resource:   "oauth_state",
		ResourceID: payload.Nonce,
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
		Context: map[string]any{
			"client_id": payload.ClientID,
		},
	})

	authURL, err := s.google.AuthCodeURL(ctx, stateToken)
	if err != nil {
		return "", err
	}
	return authURL, nil
}

// CompleteGoogleOAuth finalises Google OAuth callback and issues tokens.
func (s *Service) CompleteGoogleOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	if s.google == nil {
		return nil, ErrProviderNotEnabled
	}
	if in.Code == "" || in.State == "" {
		return nil, ErrOAuthStateInvalid
	}

	payload, err := state.Decode(s.cfg.Security.OAuthStateSecret, in.State)
	if err != nil {
		return nil, ErrOAuthStateInvalid
	}

	tenantEntity, err := s.GetTenantBySlug(ctx, payload.TenantSlug)
	if err != nil {
		return nil, err
	}

	tokenResp, err := s.google.Exchange(ctx, in.Code)
	if err != nil {
		return nil, err
	}

	profile, err := s.google.FetchProfile(ctx, tokenResp)
	if err != nil {
		return nil, err
	}
	if !profile.EmailVerified {
		return nil, ErrEmailNotVerified
	}
	if !s.isDomainAllowed(profile.Email) {
		return nil, ErrEmailDomainNotAllowed
	}

	userEntity, err := s.resolveUserFromGoogleProfile(ctx, tenantEntity, profile, tokenResp)
	if err != nil {
		return nil, err
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

	s.auditor.Record(ctx, audit.Entry{
		TenantID:   &tenantEntity.ID,
		UserID:     &userEntity.ID,
		Action:     "auth.oauth.google.success",
		Resource:   "user",
		ResourceID: userEntity.ID.String(),
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
		Context: map[string]any{
			"email": profile.Email,
		},
	})

	// Publish user.login event for OAuth
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "login", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"method":      "google",
		"ip_address":  in.IPAddress,
	})

	return result, nil
}

// StartGitHubOAuth builds the GitHub authorization URL.
func (s *Service) StartGitHubOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	if s.github == nil {
		return "", ErrProviderNotEnabled
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, in.TenantSlug)
	if err != nil {
		return "", err
	}
	payload := state.Payload{
		TenantSlug:  tenantEntity.Slug,
		ClientID:    in.ClientID,
		Flow:        defaultFlow(in.Flow),
		RedirectURI: in.RedirectURI,
		Nonce:       randomNonce(),
	}
	stateToken, err := state.Encode(s.cfg.Security.OAuthStateSecret, payload, oauthStateTTL)
	if err != nil {
		return "", fmt.Errorf("encode oauth state: %w", err)
	}
	return s.github.AuthCodeURL(ctx, stateToken)
}

// CompleteGitHubOAuth handles GitHub callback.
func (s *Service) CompleteGitHubOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	if s.github == nil {
		return nil, ErrProviderNotEnabled
	}
	if in.Code == "" || in.State == "" {
		return nil, ErrOAuthStateInvalid
	}
	payload, err := state.Decode(s.cfg.Security.OAuthStateSecret, in.State)
	if err != nil {
		return nil, ErrOAuthStateInvalid
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, payload.TenantSlug)
	if err != nil {
		return nil, err
	}
	tokenResp, err := s.github.Exchange(ctx, in.Code)
	if err != nil {
		return nil, err
	}
	profile, err := s.github.FetchProfile(ctx, tokenResp)
	if err != nil {
		return nil, err
	}
	if profile.Email == "" {
		return nil, ErrEmailNotVerified
	}
	if !s.isDomainAllowed(profile.Email) {
		return nil, ErrEmailDomainNotAllowed
	}
	userEntity, err := s.resolveUserFromGitHubProfile(ctx, tenantEntity, profile, tokenResp)
	if err != nil {
		return nil, err
	}

	// Publish user.login event for OAuth
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "login", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"method":      "github",
		"ip_address":  in.IPAddress,
	})

	return s.issueSession(ctx, issueSessionInput{
		User:      userEntity,
		Tenant:    tenantEntity,
		ClientID:  payload.ClientID,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		Scopes:    s.cfg.Token.DefaultScopes,
	})
}

// StartMicrosoftOAuth builds Microsoft authorization URL.
func (s *Service) StartMicrosoftOAuth(ctx context.Context, in OAuthStartInput) (string, error) {
	if s.microsoft == nil {
		return "", ErrProviderNotEnabled
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, in.TenantSlug)
	if err != nil {
		return "", err
	}
	payload := state.Payload{
		TenantSlug:  tenantEntity.Slug,
		ClientID:    in.ClientID,
		Flow:        defaultFlow(in.Flow),
		RedirectURI: in.RedirectURI,
		Nonce:       randomNonce(),
	}
	stateToken, err := state.Encode(s.cfg.Security.OAuthStateSecret, payload, oauthStateTTL)
	if err != nil {
		return "", fmt.Errorf("encode oauth state: %w", err)
	}
	return s.microsoft.AuthCodeURL(ctx, stateToken)
}

// CompleteMicrosoftOAuth handles Microsoft callback.
func (s *Service) CompleteMicrosoftOAuth(ctx context.Context, in OAuthCallbackInput) (*AuthResult, error) {
	if s.microsoft == nil {
		return nil, ErrProviderNotEnabled
	}
	if in.Code == "" || in.State == "" {
		return nil, ErrOAuthStateInvalid
	}
	payload, err := state.Decode(s.cfg.Security.OAuthStateSecret, in.State)
	if err != nil {
		return nil, ErrOAuthStateInvalid
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, payload.TenantSlug)
	if err != nil {
		return nil, err
	}
	tokenResp, err := s.microsoft.Exchange(ctx, in.Code)
	if err != nil {
		return nil, err
	}
	profile, err := s.microsoft.FetchProfile(ctx, tokenResp)
	if err != nil {
		return nil, err
	}
	email := profile.Mail
	if email == "" {
		email = profile.UserPrincipalName
	}
	if email == "" {
		return nil, ErrEmailNotVerified
	}
	if !s.isDomainAllowed(email) {
		return nil, ErrEmailDomainNotAllowed
	}
	userEntity, err := s.resolveUserFromMicrosoftProfile(ctx, tenantEntity, profile, tokenResp)
	if err != nil {
		return nil, err
	}

	// Publish user.login event for OAuth
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "login", map[string]any{
		"user_id":     userEntity.ID.String(),
		"email":       userEntity.Email,
		"tenant_id":   tenantEntity.ID.String(),
		"tenant_slug": tenantEntity.Slug,
		"method":      "microsoft",
		"ip_address":  in.IPAddress,
	})

	return s.issueSession(ctx, issueSessionInput{
		User:      userEntity,
		Tenant:    tenantEntity,
		ClientID:  payload.ClientID,
		IPAddress: in.IPAddress,
		UserAgent: in.UserAgent,
		Scopes:    s.cfg.Token.DefaultScopes,
	})
}

// RequestPasswordReset creates a reset token (would be emailed in production).
func (s *Service) RequestPasswordReset(ctx context.Context, in PasswordResetRequestInput) (string, error) {
	tenantEntity, err := s.GetTenantBySlug(ctx, in.TenantSlug)
	if err != nil {
		return "", err
	}
	userEntity, err := s.entClient.User.Query().
		Where(
			user.EmailEQ(normalizeEmail(in.Email)),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("query user: %w", err)
	}

	// Ensure membership exists (use First instead of Only to handle duplicate memberships gracefully)
	_, err = s.entClient.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userEntity.ID),
			tenantmembership.TenantID(tenantEntity.ID),
		).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("verify membership: %w", err)
	}

	tokenPlain, tokenHash, err := generatePasswordResetToken()
	if err != nil {
		return "", err
	}

	err = s.entClient.PasswordResetToken.Create().
		SetUserID(userEntity.ID).
		SetTokenHash(tokenHash).
		SetExpiresAt(time.Now().Add(30 * time.Minute)).
		Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("create password reset token: %w", err)
	}

	s.auditor.Record(ctx, audit.Entry{
		TenantID:   &tenantEntity.ID,
		UserID:     &userEntity.ID,
		Action:     "auth.password_reset.requested",
		Resource:   "user",
		ResourceID: userEntity.ID.String(),
		IPAddress:  in.IPAddress,
		UserAgent:  in.UserAgent,
	})

	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "password_reset.requested", map[string]any{
		"user_id":  userEntity.ID.String(),
		"email":    userEntity.Email,
		"tenant_id": tenantEntity.ID.String(),
	})

	return tokenPlain, nil
}

// ConfirmPasswordReset validates reset token and updates password.
func (s *Service) ConfirmPasswordReset(ctx context.Context, in PasswordResetConfirmInput) error {
	if err := s.validatePassword(in.NewPassword); err != nil {
		return err
	}
	hash := hashToken(in.Token)

	resetToken, err := s.entClient.PasswordResetToken.Query().
		Where(
			passwordresettoken.TokenHashEQ(hash),
			passwordresettoken.UsedAtIsNil(),
		).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrPasswordResetTokenInvalid
		}
		return fmt.Errorf("lookup reset token: %w", err)
	}
	if resetToken.ExpiresAt.Before(time.Now()) {
		return ErrPasswordResetTokenInvalid
	}

	hashedPassword, err := s.hasher.Hash(in.NewPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.entClient.User.UpdateOneID(resetToken.Edges.User.ID).
		SetPasswordHash(hashedPassword).
		Exec(ctx); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if err := s.entClient.PasswordResetToken.UpdateOneID(resetToken.ID).
		SetUsedAt(time.Now()).
		Exec(ctx); err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}

	s.auditor.Record(ctx, audit.Entry{
		UserID:     &resetToken.Edges.User.ID,
		Action:     "auth.password_reset.completed",
		Resource:   "user",
		ResourceID: resetToken.Edges.User.ID.String(),
	})

	s.publishEvent(ctx, uuid.Nil, "auth.user", resetToken.Edges.User.ID, "password_reset.completed", map[string]any{
		"user_id": resetToken.Edges.User.ID.String(),
		"email":   resetToken.Edges.User.Email,
	})

	return nil
}

// GetUser returns user by id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (*ent.User, error) {
	return s.entClient.User.Get(ctx, id)
}

// GetUserRolesAndPermissions returns the list of role names and permission codes for the user (from all tenant memberships).
// Used by GET /me to expose RBAC data for frontend nav/route guards. Can be cached in Redis with TTL.
func (s *Service) GetUserRolesAndPermissions(ctx context.Context, userID uuid.UUID) (roles []string, permissions []string, err error) {
	memberships, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(userID)).
		All(ctx)
	if err != nil {
		return nil, nil, err
	}
	roleSet := make(map[string]struct{})
	for _, m := range memberships {
		for _, r := range m.Roles {
			roleSet[r] = struct{}{}
		}
	}
	for r := range roleSet {
		roles = append(roles, r)
	}
	if len(roles) == 0 {
		return roles, nil, nil
	}
	rps, err := s.entClient.RolePermission.Query().
		Where(rolepermission.RoleNameIn(roles...)).
		WithPermission().
		All(ctx)
	if err != nil {
		return roles, nil, err
	}
	permSet := make(map[string]struct{})
	for _, rp := range rps {
		if rp.Edges.Permission != nil {
			permSet[rp.Edges.Permission.Code] = struct{}{}
		}
	}
	for p := range permSet {
		permissions = append(permissions, p)
	}
	return roles, permissions, nil
}

// ValidateAccessToken ensures the JWT is valid.
func (s *Service) ValidateAccessToken(tokenStr string) (*token.Claims, error) {
	return s.tokenSvc.Parse(tokenStr)
}

// Logout revokes session and records token revocation for provided TTL.
func (s *Service) Logout(ctx context.Context, sessionID uuid.UUID, jti string, ttl time.Duration) error {
	var sessionEntity *ent.Session
	if sessionID != uuid.Nil {
		var err error
		sessionEntity, err = s.entClient.Session.Get(ctx, sessionID)
		if err != nil {
			s.logger.Warn("failed to get session for logout", zap.Error(err))
		}
		if err := s.entClient.Session.UpdateOneID(sessionID).
			SetStatus("revoked").
			SetRevokedAt(time.Now()).
			SetRevocationReason("user_logout").
			Exec(ctx); err != nil {
			s.logger.Warn("failed to revoke session", zap.Error(err))
		}
	}
	if s.revoker != nil && jti != "" && ttl > 0 {
		_ = s.revoker.Revoke(ctx, jti, ttl)
	}

	// Publish user.logout event
	if sessionEntity != nil {
		s.publishEvent(ctx, sessionEntity.TenantID, "auth.user", sessionEntity.UserID, "logout", map[string]any{
			"user_id":    sessionEntity.UserID.String(),
			"session_id": sessionID.String(),
			"tenant_id":  sessionEntity.TenantID.String(),
		})
	}

	return nil
}

// ListSessions returns all active sessions for a user.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]*ent.Session, error) {
	return s.entClient.Session.Query().
		Where(
			session.UserID(userID),
			session.StatusEQ("active"),
		).
		Order(ent.Desc(session.FieldIssuedAt)).
		All(ctx)
}

// RevokeSession revokes a specific session owned by the user.
func (s *Service) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error {
	// Ensure the session belongs to this user
	sess, err := s.entClient.Session.Query().
		Where(
			session.IDEQ(sessionID),
			session.UserID(userID),
		).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	return s.entClient.Session.UpdateOneID(sess.ID).
		SetStatus("revoked").
		SetRevokedAt(time.Now()).
		SetRevocationReason("user_revoked").
		Exec(ctx)
}

// RevokeAllSessions revokes all sessions for a user except the specified one.
func (s *Service) RevokeAllSessions(ctx context.Context, userID uuid.UUID, exceptSessionID uuid.UUID) error {
	now := time.Now()
	_, err := s.entClient.Session.Update().
		Where(
			session.UserID(userID),
			session.StatusEQ("active"),
			session.IDNEQ(exceptSessionID),
		).
		SetStatus("revoked").
		SetRevokedAt(now).
		SetRevocationReason("user_revoked_all").
		Save(ctx)
	return err
}

type issueSessionInput struct {
	User      *ent.User
	Tenant    *ent.Tenant
	ClientID  string
	IPAddress string
	UserAgent string
	Scopes    []string
}

func (s *Service) issueSession(ctx context.Context, in issueSessionInput) (*AuthResult, error) {
	refreshPlain, refreshHash, err := s.tokenSvc.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}
	sessionCreate := s.entClient.Session.Create().
		SetUserID(in.User.ID).
		SetRefreshTokenHash(refreshHash).
		SetSessionType("user").
		SetStatus("active").
		SetExpiresAt(time.Now().Add(s.cfg.Token.RefreshTokenTTL)).
		SetClientID(in.ClientID).
		SetIPAddress(in.IPAddress).
		SetUserAgent(in.UserAgent)
	if in.Tenant != nil {
		sessionCreate.SetTenantID(in.Tenant.ID)
	}
	sessionEntity, err := sessionCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	sessionEntity.Edges.User = in.User

	return s.issueSessionWithExisting(ctx, sessionEntity, in.Tenant, refreshPlain, in.IPAddress, in.UserAgent, in.Scopes)
}

func (s *Service) issueSessionWithExisting(ctx context.Context, sessionEntity *ent.Session, tenantEntity *ent.Tenant, refreshToken string, ip string, ua string, scopes []string) (*AuthResult, error) {
	userEntity := sessionEntity.Edges.User
	if userEntity == nil {
		var err error
		userEntity, err = s.entClient.User.Get(ctx, sessionEntity.UserID)
		if err != nil {
			return nil, fmt.Errorf("load user for session: %w", err)
		}
		sessionEntity.Edges.User = userEntity
	}
	var tenantIDPtr *uuid.UUID
	if tenantEntity != nil {
		tenantIDPtr = &tenantEntity.ID
	} else if sessionEntity.TenantID != uuid.Nil {
		id := sessionEntity.TenantID
		tenantIDPtr = &id
		if t, err := s.entClient.Tenant.Get(ctx, sessionEntity.TenantID); err == nil {
			tenantEntity = t
		}
	}

	effectiveScopes := scopes
	if len(effectiveScopes) == 0 {
		effectiveScopes = s.cfg.Token.DefaultScopes
	}

	// Fetch user roles from TenantMembership
	var roles []string
	if tenantIDPtr != nil {
		membership, err := s.entClient.TenantMembership.Query().
			Where(
				tenantmembership.UserID(userEntity.ID),
				tenantmembership.TenantID(*tenantIDPtr),
			).
			Only(ctx)
		if err == nil && membership != nil {
			roles = membership.Roles
		}
	}

	// Load roles and permissions for JWT and response (canonical RBAC; matches GET /me)
	allRoles, permissions, _ := s.GetUserRolesAndPermissions(ctx, sessionEntity.UserID)
	if len(roles) == 0 && len(allRoles) > 0 {
		roles = allRoles
	}

	// Build token input with subscription data if available
	tokenInput := token.AccessTokenInput{
		UserID:      sessionEntity.UserID,
		TenantID:    tenantIDPtr,
		SessionID:   sessionEntity.ID,
		Email:       userEntity.Email,
		Scopes:      effectiveScopes,
		Roles:       roles,
		Permissions: permissions,
		IsPlatformOwner: tenantEntity != nil && tenantEntity.Slug == "codevertex",
	}
	if tenantEntity != nil {
		tokenInput.TenantSlug = tenantEntity.Slug
	}

	// Fetch subscription data for tenant (non-blocking, fail-open)
	if tenantIDPtr != nil && s.subscriptionCl != nil && s.cfg.Subscription.Enabled {
		sub, err := s.subscriptionCl.GetTenantSubscription(ctx, *tenantIDPtr)
		if err != nil {
			s.logger.Warn("failed to fetch subscription for JWT enrichment",
				zap.String("tenant_id", tenantIDPtr.String()),
				zap.Error(err),
			)
			// Continue without subscription data (fail-open)
		} else if sub != nil {
			tokenInput.SubscriptionPlan = sub.PlanCode
			tokenInput.SubscriptionStatus = sub.Status
			tokenInput.SubscriptionFeatures = sub.Features
			tokenInput.SubscriptionLimits = sub.Limits
			tokenInput.SubscriptionExpires = &sub.CurrentPeriodEnd

			// Enrich tenantEntity with subscription details for the AuthResult
			if tenantEntity != nil {
				tenantEntity.SubscriptionPlan = strPtr(sub.PlanCode)
				tenantEntity.SubscriptionStatus = strPtr(sub.Status)
				tenantEntity.SubscriptionExpiresAt = &sub.CurrentPeriodEnd
				
				// Map map[string]int to map[string]any for tier_limits
				limits := make(map[string]any)
				for k, v := range sub.Limits {
					limits[k] = v
				}
				tenantEntity.TierLimits = limits
			}
		}
	}

	// Apply branding defaults if missing
	if tenantEntity != nil {
		if tenantEntity.LogoURL == nil || *tenantEntity.LogoURL == "" {
			tenantEntity.LogoURL = strPtr("/images/logo/codevertex.png") // Platform owner default
		}
		if tenantEntity.BrandColors == nil || len(tenantEntity.BrandColors) == 0 {
			tenantEntity.BrandColors = map[string]any{
				"primary":   "#020617", // Slate 950
				"secondary": "#334155", // Slate 700
				"accent":    "#0ea5e9", // Sky 500
			}
		}
	}

	accessToken, exp, err := s.tokenSvc.MintAccessToken(tokenInput)
	if err != nil {
		return nil, fmt.Errorf("mint access token: %w", err)
	}

	if ip != "" || ua != "" {
		if err := s.entClient.Session.UpdateOneID(sessionEntity.ID).
			SetIPAddress(ip).
			SetUserAgent(ua).
			Exec(ctx); err != nil {
			s.logger.Warn("failed to update session metadata", zap.Error(err))
		}
	}

	return &AuthResult{
		User:                  userEntity,
		Tenant:                tenantEntity,
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  exp,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: sessionEntity.ExpiresAt,
		SessionID:             sessionEntity.ID,
		Roles:                 allRoles,
		Permissions:           permissions,
	}, nil
}

func (s *Service) resolveUserFromGoogleProfile(ctx context.Context, tenantEntity *ent.Tenant, profile *googleprovider.Profile, token *oauth2.Token) (*ent.User, error) {
	identity, err := s.entClient.UserIdentity.Query().
		Where(
			useridentity.ProviderEQ(googleProviderName),
			useridentity.ProviderSubjectEQ(profile.Subject),
		).
		WithUser().
		Only(ctx)
	if err == nil {
		userEntity := identity.Edges.User
		if userEntity == nil {
			userEntity, err = s.entClient.User.Get(ctx, identity.UserID)
			if err != nil {
				return nil, fmt.Errorf("load user for identity: %w", err)
			}
		}
		if err := s.ensureMembership(ctx, userEntity.ID, tenantEntity.ID); err != nil {
			return nil, err
		}
		if err := s.updateIdentityTokens(ctx, identity.ID, profile, token); err != nil {
			return nil, err
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

	email := normalizeEmail(profile.Email)
	userEntity, err := s.entClient.User.Query().
		Where(
			user.EmailEQ(email),
		).
		Only(ctx)
	isNewUser := false
	if err != nil {
		if !ent.IsNotFound(err) {
			return nil, fmt.Errorf("lookup user by email: %w", err)
		}
		userEntity, err = s.entClient.User.Create().
			SetEmail(email).
			SetStatus("active").
			SetPrimaryTenantID(tenantEntity.ID.String()).
			SetProfile(googleProfileMap(profile)).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("create user from google profile: %w", err)
		}
		isNewUser = true
	}

	if err := s.ensureMembership(ctx, userEntity.ID, tenantEntity.ID); err != nil {
		return nil, err
	}

	if err := s.createIdentity(ctx, userEntity.ID, profile, token); err != nil {
		return nil, err
	}

	if isNewUser {
		s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
			"user_id":     userEntity.ID.String(),
			"email":       userEntity.Email,
			"full_name":   profileStr(userEntity.Profile, "name"),
			"phone":       profileStr(userEntity.Profile, "phone"),
			"tenant_id":   tenantEntity.ID.String(),
			"tenant_slug": tenantEntity.Slug,
			"roles":       []string{"member"},
			"method":      "google",
		})
	}

	return userEntity, nil
}

func (s *Service) resolveUserFromGitHubProfile(ctx context.Context, tenantEntity *ent.Tenant, profile *githubprovider.Profile, token *oauth2.Token) (*ent.User, error) {
	sub := fmt.Sprintf("%d", profile.ID)
	email := normalizeEmail(profile.Email)
	if email == "" {
		return nil, fmt.Errorf("github email not available")
	}
	identity, err := s.entClient.UserIdentity.Query().
		Where(
			useridentity.ProviderEQ(githubProviderName),
			useridentity.ProviderSubjectEQ(sub),
		).
		WithUser().
		Only(ctx)
	if err == nil {
		userEntity := identity.Edges.User
		if err := s.ensureMembership(ctx, userEntity.ID, tenantEntity.ID); err != nil {
			return nil, err
		}
		if err := s.updateIdentityTokens(ctx, identity.ID, &googleprovider.Profile{Email: email, Name: profile.Name}, token); err != nil {
			return nil, err
		}
		return userEntity, nil
	}
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("query user identity: %w", err)
	}
	userEntity, err := s.entClient.User.Query().
		Where(user.EmailEQ(email)).
		Only(ctx)
	isNewUser := false
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	if err != nil && ent.IsNotFound(err) {
		userEntity, err = s.entClient.User.Create().
			SetEmail(email).
			SetStatus("active").
			SetPrimaryTenantID(tenantEntity.ID.String()).
			SetProfile(map[string]any{"name": profile.Name}).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		isNewUser = true
	}
	if err := s.ensureMembership(ctx, userEntity.ID, tenantEntity.ID); err != nil {
		return nil, err
	}
	if err := s.createIdentity(ctx, userEntity.ID, &googleprovider.Profile{Subject: sub, Email: email, Name: profile.Name}, token); err != nil {
		return nil, err
	}
	if isNewUser {
		s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
			"user_id":     userEntity.ID.String(),
			"email":       userEntity.Email,
			"full_name":   profileStr(userEntity.Profile, "name"),
			"phone":       profileStr(userEntity.Profile, "phone"),
			"tenant_id":   tenantEntity.ID.String(),
			"tenant_slug": tenantEntity.Slug,
			"roles":       []string{"member"},
			"method":      "github",
		})
	}
	return userEntity, nil
}

func (s *Service) resolveUserFromMicrosoftProfile(ctx context.Context, tenantEntity *ent.Tenant, profile *microsoftprovider.Profile, token *oauth2.Token) (*ent.User, error) {
	email := profile.Mail
	if email == "" {
		email = profile.UserPrincipalName
	}
	email = normalizeEmail(email)
	if email == "" {
		return nil, fmt.Errorf("microsoft email not available")
	}
	sub := profile.ID
	identity, err := s.entClient.UserIdentity.Query().
		Where(
			useridentity.ProviderEQ(microsoftProviderName),
			useridentity.ProviderSubjectEQ(sub),
		).
		WithUser().
		Only(ctx)
	if err == nil {
		userEntity := identity.Edges.User
		if err := s.ensureMembership(ctx, userEntity.ID, tenantEntity.ID); err != nil {
			return nil, err
		}
		if err := s.updateIdentityTokens(ctx, identity.ID, &googleprovider.Profile{Email: email, Name: profile.DisplayName}, token); err != nil {
			return nil, err
		}
		return userEntity, nil
	}
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("query user identity: %w", err)
	}
	userEntity, err := s.entClient.User.Query().
		Where(user.EmailEQ(email)).
		Only(ctx)
	isNewUser := false
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	if err != nil && ent.IsNotFound(err) {
		userEntity, err = s.entClient.User.Create().
			SetEmail(email).
			SetStatus("active").
			SetPrimaryTenantID(tenantEntity.ID.String()).
			SetProfile(map[string]any{"name": profile.DisplayName}).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		isNewUser = true
	}
	if err := s.ensureMembership(ctx, userEntity.ID, tenantEntity.ID); err != nil {
		return nil, err
	}
	if err := s.createIdentity(ctx, userEntity.ID, &googleprovider.Profile{Subject: sub, Email: email, Name: profile.DisplayName}, token); err != nil {
		return nil, err
	}
	if isNewUser {
		s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
			"user_id":     userEntity.ID.String(),
			"email":       userEntity.Email,
			"full_name":   profileStr(userEntity.Profile, "name"),
			"phone":       profileStr(userEntity.Profile, "phone"),
			"tenant_id":   tenantEntity.ID.String(),
			"tenant_slug": tenantEntity.Slug,
			"roles":       []string{"member"},
			"method":      "microsoft",
		})
	}
	return userEntity, nil
}
func (s *Service) updateIdentityTokens(ctx context.Context, identityID uuid.UUID, profile *googleprovider.Profile, token *oauth2.Token) error {
	update := s.entClient.UserIdentity.UpdateOneID(identityID).
		SetProviderEmail(normalizeEmail(profile.Email)).
		SetEmailVerified(profile.EmailVerified).
		SetTokenExpiry(tokenExpiry(token)).
		SetProfile(googleProfileMap(profile)).
		SetScope(scopeFromToken(token))

	if token.AccessToken != "" {
		update.SetAccessToken(token.AccessToken)
	} else {
		update.ClearAccessToken()
	}
	if token.RefreshToken != "" {
		update.SetRefreshToken(token.RefreshToken)
	} else {
		update.ClearRefreshToken()
	}

	if err := update.Exec(ctx); err != nil {
		return fmt.Errorf("update identity tokens: %w", err)
	}
	return nil
}

func (s *Service) createIdentity(ctx context.Context, userID uuid.UUID, profile *googleprovider.Profile, token *oauth2.Token) error {
	identityCreate := s.entClient.UserIdentity.Create().
		SetUserID(userID).
		SetProvider(googleProviderName).
		SetProviderSubject(profile.Subject).
		SetProviderEmail(normalizeEmail(profile.Email)).
		SetEmailVerified(profile.EmailVerified).
		SetTokenExpiry(tokenExpiry(token)).
		SetScope(scopeFromToken(token)).
		SetProfile(googleProfileMap(profile))

	if token != nil {
		if token.AccessToken != "" {
			identityCreate.SetAccessToken(token.AccessToken)
		}
		if token.RefreshToken != "" {
			identityCreate.SetRefreshToken(token.RefreshToken)
		}
	}

	if _, err := identityCreate.Save(ctx); err != nil {
		return fmt.Errorf("create user identity: %w", err)
	}
	return nil
}

func (s *Service) ensureMembership(ctx context.Context, userID, tenantID uuid.UUID) error {
	exists, err := s.entClient.TenantMembership.Query().
		Where(
			tenantmembership.UserID(userID),
			tenantmembership.TenantID(tenantID),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("check tenant membership: %w", err)
	}
	if exists {
		return nil
	}
	_, err = s.entClient.TenantMembership.Create().
		SetUserID(userID).
		SetTenantID(tenantID).
		SetRoles([]string{"member"}).
		Save(ctx)
	if err != nil {
		// Ignore constraint errors (membership already exists due to race condition)
		if ent.IsConstraintError(err) {
			s.logger.Warn("tenant membership already exists (race condition)", zap.String("user_id", userID.String()), zap.String("tenant_id", tenantID.String()))
			return nil
		}
		return fmt.Errorf("create tenant membership: %w", err)
	}
	return nil
}

func (s *Service) isDomainAllowed(email string) bool {
	allowed := s.cfg.Providers.Google.AllowedDomains
	if len(allowed) == 0 {
		return true
	}
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.TrimSpace(parts[1])
	for _, allowedDomain := range allowed {
		if strings.EqualFold(domain, strings.TrimSpace(allowedDomain)) {
			return true
		}
	}
	return false
}

func tokenExpiry(token *oauth2.Token) time.Time {
	if token == nil || token.Expiry.IsZero() {
		return time.Now().Add(5 * time.Minute)
	}
	return token.Expiry
}

func scopeFromToken(token *oauth2.Token) string {
	if token == nil {
		return ""
	}
	if scope := token.Extra("scope"); scope != nil {
		return fmt.Sprintf("%v", scope)
	}
	return ""
}

func googleProfileMap(profile *googleprovider.Profile) map[string]any {
	if profile == nil {
		return map[string]any{}
	}
	return map[string]any{
		"name":    profile.Name,
		"picture": profile.Picture,
		"locale":  profile.Locale,
	}
}

func defaultFlow(flow string) string {
	if flow == "" {
		return "login"
	}
	return strings.ToLower(flow)
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return uuid.New().String()
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Service) validatePassword(password string) error {
	if len(password) < s.cfg.Security.PasswordMinLength {
		return ErrPasswordTooWeak
	}
	return nil
}

func (s *Service) GetTenantBySlug(ctx context.Context, slug string) (*ent.Tenant, error) {
	if slug == "" {
		return nil, ErrTenantNotFound
	}
	tenantEntity, err := s.entClient.Tenant.Query().
		Where(tenant.SlugEQ(slug)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("query tenant: %w", err)
	}
	// Reject auth attempts against inactive/suspended tenants
	if tenantEntity.Status != "active" {
		return nil, ErrTenantInactive
	}
	return tenantEntity, nil
}

func (s *Service) recordLoginAttempt(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, email string, success bool, reason string, ip string, ua string) {
	builder := s.entClient.LoginAttempt.Create().
		SetTenantID(tenantID).
		SetEmail(normalizeEmail(email)).
		SetSuccess(success).
		SetFailureReason(reason).
		SetIPAddress(ip).
		SetUserAgent(ua)
	if userID != uuid.Nil {
		builder.SetUserID(userID)
	}
	if err := builder.Exec(ctx); err != nil {
		s.logger.Warn("failed to record login attempt", zap.Error(err))
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generatePasswordResetToken() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("random reset token: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(buf)
	return plain, hashToken(plain), nil
}

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

// publishEvent writes an event to the outbox table for async NATS publishing.
// Best-effort: failures are logged but do not block the caller.
func (s *Service) publishEvent(ctx context.Context, tenantID uuid.UUID, aggregateType string, aggregateID uuid.UUID, eventType string, data map[string]any) {
	event := sharedevents.Event{
		ID:            uuid.New(),
		TenantID:      tenantID,
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		EventType:     eventType,
		Payload:       data,
		Timestamp:     time.Now().UTC(),
		Version:       "1.0",
	}

	payload, err := json.Marshal(event)
	if err != nil {
		s.logger.Warn("failed to marshal outbox event",
			zap.String("event_type", eventType),
			zap.Error(err))
		return
	}

	err = s.entClient.OutboxEvent.Create().
		SetTenantID(tenantID).
		SetAggregateType(aggregateType).
		SetAggregateID(aggregateID).
		SetEventType(eventType).
		SetPayload(payload).
		SetStatus(outboxevent.StatusPENDING).
		SetAttempts(0).
		Exec(ctx)
	if err != nil {
		s.logger.Warn("failed to write outbox event",
			zap.String("event_type", eventType),
			zap.Error(err))
	}
}

func coalesceMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	return input
}

// profileStr extracts a string value from a user's Profile JSON map.
func profileStr(profile map[string]any, key string) string {
	if profile == nil {
		return ""
	}
	if v, ok := profile[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func strPtr(s string) *string {
	return &s
}
