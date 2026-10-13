package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/oauthclient"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ErrRoleNotAllowed is returned when a public registration asks for a role people may not give
// themselves (any staff or admin role). Staff roles come only from an invite or a tenant admin.
var ErrRoleNotAllowed = errors.New("role cannot be self-assigned")

// selfServiceRoles are the only roles a person may take on in a tenant without an invite: the
// customer of a storefront, a learner or a learner's parent, and a rider applicant (riders are
// not dispatchable until logistics approves their KYC). "member" is the long-standing default of
// the auth-ui "Join organisation" signup and carries no service permissions on its own.
var selfServiceRoles = map[string]bool{
	"member":   true,
	"customer": true,
	"student":  true,
	"parent":   true,
	"driver":   true,
}

// IsSelfServiceRole reports whether role may be self-assigned at signup.
func IsSelfServiceRole(role string) bool {
	return selfServiceRoles[strings.TrimSpace(role)]
}

// clientSelfSignupRoleKey is the OAuthClient metadata key that marks a customer-facing app. Its
// value is the role a signed-in person gets in the requested tenant when they have none yet
// (ordering-ui: customer, rider-app: driver, codevertex-website: student). Staff apps leave it
// unset, so they keep requiring an invite.
const clientSelfSignupRoleKey = "self_signup_role"

// SelfSignupRole returns the role clientID lets people join a tenant with, or "" when the client
// is not customer-facing (or unknown). Only self-service roles are honoured, so a mistyped or
// tampered metadata value can never grant staff access.
func (s *Service) SelfSignupRole(ctx context.Context, clientID string) string {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return ""
	}
	c, err := s.entClient.OAuthClient.Query().Where(oauthclient.ClientID(clientID)).Only(ctx)
	if err != nil {
		return ""
	}
	role, _ := c.Metadata[clientSelfSignupRoleKey].(string)
	role = strings.TrimSpace(role)
	if role == "" || role == "member" || !IsSelfServiceRole(role) {
		return ""
	}
	return role
}

// JoinAsSelfServiceMember gives userID a membership in tenantSlug with the client's self-signup
// role when the client is customer-facing and the user has no membership there yet. It returns
// true when the user is (now) a member. Existing memberships are never changed: a staff member
// signing in to the storefront keeps their staff roles.
func (s *Service) JoinAsSelfServiceMember(ctx context.Context, userID uuid.UUID, tenantSlug, clientID string) (bool, error) {
	role := s.SelfSignupRole(ctx, clientID)
	if role == "" || strings.TrimSpace(tenantSlug) == "" {
		return false, nil
	}
	tenantEntity, err := s.GetTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return false, nil
	}
	userEntity, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	if !UserCanSignIn(userEntity.Status) {
		return false, ErrAccountDisabled
	}
	return s.joinTenantAs(ctx, userEntity, tenantEntity, role, "self_signup")
}

// joinTenantAs creates the membership (idempotent under the user+tenant unique index) and
// publishes auth.user.created so the tenant's services provision the person, exactly like a
// registration into an existing tenant does.
func (s *Service) joinTenantAs(ctx context.Context, userEntity *ent.User, tenantEntity *ent.Tenant, role, method string) (bool, error) {
	exists, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(userEntity.ID), tenantmembership.TenantID(tenantEntity.ID)).
		Exist(ctx)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	if _, err := s.entClient.TenantMembership.Create().
		SetUserID(userEntity.ID).
		SetTenantID(tenantEntity.ID).
		SetRoles([]string{role}).
		SetStatus("active").
		Save(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return true, nil
		}
		return false, err
	}
	s.logger.Info("self-service tenant join",
		zap.String("user_id", userEntity.ID.String()),
		zap.String("tenant", tenantEntity.Slug),
		zap.String("role", role))
	s.publishEvent(ctx, tenantEntity.ID, "auth.user", userEntity.ID, "created", map[string]any{
		"user_id":        userEntity.ID.String(),
		"email":          userEntity.Email,
		"full_name":      profileStr(userEntity.Profile, "name"),
		"phone":          profileStr(userEntity.Profile, "phone"),
		"tenant_id":      tenantEntity.ID.String(),
		"tenant_slug":    tenantEntity.Slug,
		"roles":          []string{role},
		"method":         method,
		"email_verified": userEntity.EmailVerified,
	})
	return true, nil
}
