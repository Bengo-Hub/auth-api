package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/mfabackupcode"
	"github.com/bengobox/auth-api/internal/ent/mfasettings"
	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
	"github.com/bengobox/auth-api/internal/ent/role"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/services/usecase"
)

// Authentication method references carried in the access token's amr claim. The first five are
// RFC 8176 values; totp names an authenticator app code and mfa is added once a second factor
// was verified. Resource servers gate staff routes on amr containing AMRMFA.
const (
	AMRPassword  = "pwd"
	AMROTP       = "otp"
	AMRFederated = "fed"
	AMRPasskey   = "hwk"
	AMRPIN       = "pin"
	AMRTOTP      = "totp"
	AMRMFA       = "mfa"
)

// Metadata keys of the MFA policy. A tenant's own policy lives in its metadata under
// TenantMetadataMFAPolicy; the default for every tenant without one lives in the platform
// tenant's metadata under PlatformMetadataMFAPolicyDefault. Only a platform owner writes either.
const (
	TenantMetadataMFAPolicy          = "mfa_policy"
	PlatformMetadataMFAPolicyDefault = "mfa_policy_default"
)

// Session metadata keys holding what the sign-in proved. Refresh reads them back and never adds
// to them.
const (
	sessionMetadataAMR           = "amr"
	sessionMetadataMFAEnrollment = "mfa_enrollment_required"
)

// ErrMFARequired is returned when a sign-in covered by an MFA policy reaches session issuance
// without the authenticator code, for an account that has one. The person signs in again and
// enters the code.
var ErrMFARequired = errors.New("authenticator code required")

// MFAPolicy says which members must sign in with a second factor. A member is covered when they
// hold one of RequiredRoles in the tenant, or when AllAccounts is on.
type MFAPolicy struct {
	RequiredRoles []string `json:"required_roles"`
	AllAccounts   bool     `json:"all_accounts"`
}

// Normalized trims, drops empty and duplicate role codes and sorts them, so stored policies
// compare equal however they were typed.
func (p MFAPolicy) Normalized() MFAPolicy {
	seen := map[string]bool{}
	roles := make([]string, 0, len(p.RequiredRoles))
	for _, r := range p.RequiredRoles {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		roles = append(roles, r)
	}
	sort.Strings(roles)
	return MFAPolicy{RequiredRoles: roles, AllAccounts: p.AllAccounts}
}

// Covers reports whether a member holding roles must use a second factor under this policy.
func (p MFAPolicy) Covers(roles []string) bool {
	if p.AllAccounts {
		return true
	}
	for _, want := range p.RequiredRoles {
		for _, have := range roles {
			if have == want {
				return true
			}
		}
	}
	return false
}

// IsEmpty reports whether the policy requires nothing of anyone.
func (p MFAPolicy) IsEmpty() bool { return !p.AllAccounts && len(p.RequiredRoles) == 0 }

// MetadataValue is the policy as stored in tenant metadata.
func (p MFAPolicy) MetadataValue() map[string]any {
	n := p.Normalized()
	return map[string]any{"required_roles": n.RequiredRoles, "all_accounts": n.AllAccounts}
}

// ParseMFAPolicy reads a policy from a metadata value. ok is false when the value is absent or is
// not an object, which means "no policy set here". Role codes that are not strings are ignored.
func ParseMFAPolicy(v any) (MFAPolicy, bool) {
	m, isMap := v.(map[string]any)
	if !isMap {
		return MFAPolicy{}, false
	}
	var p MFAPolicy
	switch roles := m["required_roles"].(type) {
	case []any:
		for _, r := range roles {
			if s, ok := r.(string); ok {
				p.RequiredRoles = append(p.RequiredRoles, s)
			}
		}
	case []string:
		p.RequiredRoles = append(p.RequiredRoles, roles...)
	}
	p.AllAccounts, _ = m["all_accounts"].(bool)
	return p.Normalized(), true
}

// TenantMFAPolicy returns the tenant's own policy and whether it has one.
func TenantMFAPolicy(t *ent.Tenant) (MFAPolicy, bool) {
	if t == nil {
		return MFAPolicy{}, false
	}
	return ParseMFAPolicy(t.Metadata[TenantMetadataMFAPolicy])
}

// platformDefaultTTL is how long a pod reuses the platform default policy it read. Every sign-in
// and refresh would otherwise read the platform tenant; a change made through the policy route
// clears this pod's copy at once and reaches the others within this time.
const platformDefaultTTL = 30 * time.Second

type cachedPlatformDefault struct {
	policy MFAPolicy
	at     time.Time
}

// platformDefaultCache is keyed by the ent client, so services (and tests) with their own
// database never share an entry.
var platformDefaultCache = struct {
	sync.Mutex
	entries map[*ent.Client]cachedPlatformDefault
}{entries: map[*ent.Client]cachedPlatformDefault{}}

func (s *Service) forgetPlatformDefault() {
	platformDefaultCache.Lock()
	delete(platformDefaultCache.entries, s.entClient)
	platformDefaultCache.Unlock()
}

// PlatformMFAPolicyDefault returns the platform default policy. A platform without the platform
// tenant, or without the key, requires nothing.
func (s *Service) PlatformMFAPolicyDefault(ctx context.Context) (MFAPolicy, error) {
	platformDefaultCache.Lock()
	c, ok := platformDefaultCache.entries[s.entClient]
	platformDefaultCache.Unlock()
	if ok && time.Since(c.at) < platformDefaultTTL {
		return c.policy, nil
	}
	pt, err := s.entClient.Tenant.Query().Where(tenant.SlugEQ(platformTenantSlug)).Only(ctx)
	var p MFAPolicy
	switch {
	case err == nil:
		p, _ = ParseMFAPolicy(pt.Metadata[PlatformMetadataMFAPolicyDefault])
		p = p.Normalized()
	case ent.IsNotFound(err):
		p = MFAPolicy{RequiredRoles: []string{}}
	default:
		return MFAPolicy{}, fmt.Errorf("load platform tenant: %w", err)
	}
	platformDefaultCache.Lock()
	platformDefaultCache.entries[s.entClient] = cachedPlatformDefault{policy: p, at: time.Now()}
	platformDefaultCache.Unlock()
	return p, nil
}

// MFAPolicySource names where an effective policy came from.
type MFAPolicySource string

const (
	MFAPolicyFromTenant   MFAPolicySource = "tenant"
	MFAPolicyFromPlatform MFAPolicySource = "platform"
)

// EffectiveMFAPolicy is the tenant's own policy when it has one, the platform default otherwise.
// A nil tenant (no organisation resolved) gets the platform default.
func (s *Service) EffectiveMFAPolicy(ctx context.Context, t *ent.Tenant) (MFAPolicy, MFAPolicySource, error) {
	if p, ok := TenantMFAPolicy(t); ok {
		return p, MFAPolicyFromTenant, nil
	}
	p, err := s.PlatformMFAPolicyDefault(ctx)
	return p, MFAPolicyFromPlatform, err
}

// mfaStatus is what a sign-in owes under the MFA policy.
type mfaStatus struct {
	// covered: the effective policy (or a platform admin's per-user enforcement) requires a
	// second factor for this member in this tenant.
	covered bool
	// hasAuthenticator: the account has an enabled authenticator app.
	hasAuthenticator bool
}

// mfaStatusFor decides coverage and authenticator presence for one member signing in to one
// tenant. Both lookups fail closed: an error counts as covered and as having an authenticator,
// so the caller asks for a code that cannot be skipped rather than issuing a full session.
func (s *Service) mfaStatusFor(ctx context.Context, userID uuid.UUID, t *ent.Tenant) mfaStatus {
	st, err := s.mfaStatusChecked(ctx, userID, t)
	if err != nil {
		s.logger.Warn("mfa policy: lookup failed, failing closed", zap.String("user_id", userID.String()), zap.Error(err))
		return mfaStatus{covered: true, hasAuthenticator: true}
	}
	return st
}

// mfaStatusChecked is mfaStatusFor that returns a lookup error instead of failing closed, for the
// refresh path, where a brief database error must be retried rather than signing people out. The
// authenticator is looked up only for a covered member, so an uncovered refresh costs no more.
func (s *Service) mfaStatusChecked(ctx context.Context, userID uuid.UUID, t *ent.Tenant) (mfaStatus, error) {
	covered, err := s.mfaCovers(ctx, userID, t)
	if err != nil {
		return mfaStatus{}, err
	}
	if !covered {
		return mfaStatus{}, nil
	}
	on, err := s.IsMFAEnabled(ctx, userID)
	if err != nil {
		return mfaStatus{}, fmt.Errorf("load authenticator: %w", err)
	}
	return mfaStatus{covered: true, hasAuthenticator: on}, nil
}

// mfaCovers reports whether the member must sign in with a second factor: a policy covers one of
// their roles (or every account), or a platform admin turned on enforcement for this one account
// (POST /admin/users/{id}/mfa-enforcement).
//
// Shared demo logins are never covered: their credentials are public and authenticator setup is
// refused for them (handlers.demoSelfServiceBlocked). A demo tenant is recognised only by the
// guarded IsDemo column and its slug, never by tenant metadata a tenant admin can write. A demo
// account is recognised by profile is_demo, which only a platform admin can set: registration
// strips it (withoutRegistrantOnlyKeys) and the self-service profile route accepts named fields only.
func (s *Service) mfaCovers(ctx context.Context, userID uuid.UUID, t *ent.Tenant) (bool, error) {
	if isDemoTenant(t) {
		return false, nil
	}
	covered, err := s.mfaPolicyCovers(ctx, userID, t)
	if err != nil || !covered {
		return covered, err
	}
	u, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		return true, fmt.Errorf("load user: %w", err)
	}
	demo, _ := u.Profile["is_demo"].(bool)
	return !demo, nil
}

// isDemoTenant recognises the shared demo tenant by what only the platform sets.
func isDemoTenant(t *ent.Tenant) bool {
	return t != nil && (t.IsDemo || t.Slug == "codevertex-demo")
}

// mfaPolicyCovers applies the policies and the per-user enforcement. Every membership the account
// holds is checked, not only the tenant named at sign-in: a platform owner may sign in to any tenant
// without a membership there, a passkey sign-in names any tenant, and roles can come from another
// tenant when the named one grants none. Naming a tenant with a weaker policy therefore never lowers
// what the account must prove. A demo membership is skipped like the demo tenant itself.
func (s *Service) mfaPolicyCovers(ctx context.Context, userID uuid.UUID, t *ent.Tenant) (bool, error) {
	policy, _, err := s.EffectiveMFAPolicy(ctx, t)
	if err != nil {
		return true, err
	}
	if policy.AllAccounts {
		return true, nil
	}
	memberships, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(userID)).
		WithTenant().
		All(ctx)
	if err != nil {
		return true, fmt.Errorf("load memberships: %w", err)
	}
	var platformDefault *MFAPolicy
	for _, m := range memberships {
		if isDemoTenant(m.Edges.Tenant) {
			continue
		}
		p := policy
		if t == nil || m.TenantID != t.ID {
			if own, ok := TenantMFAPolicy(m.Edges.Tenant); ok {
				p = own
			} else {
				if platformDefault == nil {
					d, dErr := s.PlatformMFAPolicyDefault(ctx)
					if dErr != nil {
						return true, dErr
					}
					platformDefault = &d
				}
				p = *platformDefault
			}
		}
		if p.AllAccounts || p.Covers(m.Roles) {
			return true, nil
		}
	}
	enforced, err := s.entClient.MFASettings.Query().
		Where(mfasettings.UserID(userID), mfasettings.EnforcedAtNotNil()).
		Exist(ctx)
	if err != nil {
		return true, fmt.Errorf("load mfa enforcement: %w", err)
	}
	return enforced, nil
}

// MFACovered reports, for callers outside this package, whether the policy covers the member in
// the tenant and whether the account has an authenticator, with the same fail-closed rules.
func (s *Service) MFACovered(ctx context.Context, userID uuid.UUID, t *ent.Tenant) (covered, hasAuthenticator bool) {
	st := s.mfaStatusFor(ctx, userID, t)
	return st.covered, st.hasAuthenticator
}

// OIDCStepUp is what the authorize and token endpoints owe for a member whose single sign-on
// session proved amr, signing in to the tenant named by tenantSlug (empty: their primary tenant).
type OIDCStepUp int

const (
	// OIDCStepUpNone: the token may be issued as usual.
	OIDCStepUpNone OIDCStepUp = iota
	// OIDCStepUpSignIn: covered and the account has an authenticator, but the session never proved
	// it. The person signs in again and enters the code.
	OIDCStepUpSignIn
	// OIDCStepUpEnroll: covered and no authenticator. Only an enrolment-only token may be issued.
	OIDCStepUpEnroll
)

// OIDCStepUpFor applies the policy to an authorization request or code exchange. A session that
// already proved a second factor needs nothing more.
func (s *Service) OIDCStepUpFor(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, amr []string) OIDCStepUp {
	if hasMethod(amr, AMRMFA) {
		return OIDCStepUpNone
	}
	var t *ent.Tenant
	if tenantID != nil {
		loaded, err := s.entClient.Tenant.Get(ctx, *tenantID)
		if err != nil {
			s.logger.Warn("mfa policy: tenant lookup failed, failing closed", zap.String("tenant_id", tenantID.String()), zap.Error(err))
			return OIDCStepUpSignIn
		}
		t = loaded
	}
	st := s.mfaStatusFor(ctx, userID, t)
	switch {
	case !st.covered:
		return OIDCStepUpNone
	case st.hasAuthenticator:
		return OIDCStepUpSignIn
	default:
		return OIDCStepUpEnroll
	}
}

// OIDCStepUpForSlug is OIDCStepUpFor for the authorize endpoint, which knows the tenant by slug.
// An unknown slug needs nothing here: the code exchange refuses it anyway.
func (s *Service) OIDCStepUpForSlug(ctx context.Context, userID uuid.UUID, tenantSlug string, amr []string) OIDCStepUp {
	if strings.TrimSpace(tenantSlug) == "" {
		u, err := s.entClient.User.Get(ctx, userID)
		if err != nil {
			return OIDCStepUpSignIn
		}
		if id, perr := uuid.Parse(u.PrimaryTenantID); perr == nil {
			return s.OIDCStepUpFor(ctx, userID, &id, amr)
		}
		return s.OIDCStepUpFor(ctx, userID, nil, amr)
	}
	t, err := s.entClient.Tenant.Query().Where(tenant.SlugEQ(strings.TrimSpace(tenantSlug))).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return OIDCStepUpNone
		}
		return OIDCStepUpSignIn
	}
	return s.OIDCStepUpFor(ctx, userID, &t.ID, amr)
}

// ── Policy administration (platform owners only; the handler checks and audits) ──

// MFAPolicyView is what the admin screens show for one scope.
type MFAPolicyView struct {
	// Policy is the stored policy for the scope. For a tenant without its own, it is empty and
	// Inherited is true.
	Policy MFAPolicy `json:"policy"`
	// Inherited is true when the tenant has no policy of its own and follows the platform default.
	Inherited bool `json:"inherited"`
	// Effective is the policy sign-ins in this scope follow.
	Effective MFAPolicy `json:"effective"`
	// AvailableRoles are the role codes to pick from: the role catalogue, the roles members of the
	// tenant hold, and any code already in the policy.
	AvailableRoles []string `json:"available_roles"`
}

// GetPlatformMFAPolicy returns the platform default policy view.
func (s *Service) GetPlatformMFAPolicy(ctx context.Context) (*MFAPolicyView, error) {
	p, err := s.PlatformMFAPolicyDefault(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := s.mfaRoleChoices(ctx, nil, p)
	if err != nil {
		return nil, err
	}
	return &MFAPolicyView{Policy: p, Effective: p, AvailableRoles: roles}, nil
}

// SetPlatformMFAPolicy stores the platform default policy in the platform tenant's metadata.
func (s *Service) SetPlatformMFAPolicy(ctx context.Context, p MFAPolicy) (*MFAPolicyView, error) {
	err := s.updateTenantMetadata(ctx,
		func() (*ent.Tenant, error) {
			return s.entClient.Tenant.Query().Where(tenant.SlugEQ(platformTenantSlug)).Only(ctx)
		},
		func(meta map[string]any) { meta[PlatformMetadataMFAPolicyDefault] = p.MetadataValue() })
	s.forgetPlatformDefault()
	if err != nil {
		return nil, fmt.Errorf("save platform mfa policy: %w", err)
	}
	return s.GetPlatformMFAPolicy(ctx)
}

// GetTenantMFAPolicy returns one tenant's policy view.
func (s *Service) GetTenantMFAPolicy(ctx context.Context, tenantID uuid.UUID) (*MFAPolicyView, error) {
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	own, hasOwn := TenantMFAPolicy(t)
	effective, _, err := s.EffectiveMFAPolicy(ctx, t)
	if err != nil {
		return nil, err
	}
	view := &MFAPolicyView{Policy: own, Inherited: !hasOwn, Effective: effective}
	if !hasOwn {
		view.Policy = MFAPolicy{RequiredRoles: []string{}}
	}
	view.AvailableRoles, err = s.mfaRoleChoices(ctx, &t.ID, effective)
	if err != nil {
		return nil, err
	}
	return view, nil
}

// SetTenantMFAPolicy stores a tenant's own policy, or removes it (inherit) so the tenant follows
// the platform default again.
func (s *Service) SetTenantMFAPolicy(ctx context.Context, tenantID uuid.UUID, p MFAPolicy, inherit bool) (*MFAPolicyView, error) {
	err := s.updateTenantMetadata(ctx, func() (*ent.Tenant, error) { return s.entClient.Tenant.Get(ctx, tenantID) },
		func(meta map[string]any) {
			if inherit {
				delete(meta, TenantMetadataMFAPolicy)
			} else {
				meta[TenantMetadataMFAPolicy] = p.MetadataValue()
			}
		})
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("save tenant mfa policy: %w", err)
	}
	return s.GetTenantMFAPolicy(ctx, tenantID)
}

// ErrUserNotFound is returned when an admin action names a user that does not exist.
var ErrUserNotFound = errors.New("user not found")

// MFAResetResult reports what ResetUserMFA removed.
type MFAResetResult struct {
	HadAuthenticator bool
	SessionsRevoked  int
}

// ResetUserMFA removes the user's authenticator app and backup codes and revokes every active
// session, in one transaction. Access tokens already issued run out on their own short expiry; no
// session remains to refresh them.
func (s *Service) ResetUserMFA(ctx context.Context, userID uuid.UUID) (*MFAResetResult, error) {
	if _, err := s.entClient.User.Get(ctx, userID); err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("load user: %w", err)
	}
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	removed, err := tx.MFATOTPSecret.Delete().Where(mfatotpsecret.UserID(userID)).Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("remove authenticator: %w", err)
	}
	if _, err := tx.MFABackupCode.Delete().Where(mfabackupcode.UserID(userID)).Exec(ctx); err != nil {
		return nil, fmt.Errorf("remove backup codes: %w", err)
	}
	revoked, err := tx.Session.Update().
		Where(session.UserID(userID), session.StatusEQ("active")).
		SetStatus("revoked").
		SetRevokedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("revoke sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &MFAResetResult{HadAuthenticator: removed > 0, SessionsRevoked: revoked}, nil
}

// metadataWriteAttempts bounds the retries of a metadata write that lost a race.
const metadataWriteAttempts = 5

// updateTenantMetadata changes one tenant's metadata map with a compare-and-swap on updated_at, so
// a concurrent save of the same row (the tenant settings form writes the whole map) is never
// overwritten: the change is re-applied to the newer row instead.
func (s *Service) updateTenantMetadata(ctx context.Context, load func() (*ent.Tenant, error), change func(map[string]any)) error {
	for attempt := 0; attempt < metadataWriteAttempts; attempt++ {
		t, err := load()
		if err != nil {
			return err
		}
		meta := copyMetadata(t.Metadata)
		change(meta)
		n, err := s.entClient.Tenant.Update().
			Where(tenant.ID(t.ID), tenant.UpdatedAtEQ(t.UpdatedAt)).
			SetMetadata(meta).
			Save(ctx)
		if err != nil {
			return err
		}
		if n == 1 {
			return nil
		}
	}
	return errors.New("tenant metadata kept changing; try again")
}

// roleScopesFor is the role scopes of a tenant's use cases: "hadia-api" gives scope "hadia".
func roleScopesFor(primary string, useCases []string) map[string]bool {
	scopes := map[string]bool{}
	for _, uc := range append([]string{primary}, useCases...) {
		for _, svc := range usecase.ApplicableServices(uc) {
			scopes[strings.SplitN(svc, "-", 2)[0]] = true
		}
	}
	return scopes
}

// roleFitsTenant reports whether a catalogue role belongs in a tenant's editor. The catalogue is
// global, so without this a gift registry was offered barista and doctor.
func roleFitsTenant(code, scope string, scopes map[string]bool) bool {
	return code == "admin" || code == "superuser" || scopes[scope]
}

// mfaRoleChoices lists the role codes the policy editor offers: for the platform default every
// catalogue role; for a tenant the roles of its use cases, the ones its members hold, and any
// already in the policy.
func (s *Service) mfaRoleChoices(ctx context.Context, tenantID *uuid.UUID, current MFAPolicy) ([]string, error) {
	set := map[string]bool{}
	roles, err := s.entClient.Role.Query().Select(role.FieldRoleCode, role.FieldScope).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	var scopes map[string]bool
	if tenantID != nil {
		t, err := s.entClient.Tenant.Get(ctx, *tenantID)
		if err != nil {
			return nil, fmt.Errorf("read tenant: %w", err)
		}
		primary := ""
		if t.UseCase != nil {
			primary = *t.UseCase
		}
		scopes = roleScopesFor(primary, t.UseCases)
	}
	for _, r := range roles {
		if scopes == nil || roleFitsTenant(r.RoleCode, r.Scope, scopes) {
			set[r.RoleCode] = true
		}
	}
	if tenantID != nil {
		ms, err := s.entClient.TenantMembership.Query().Where(tenantmembership.TenantID(*tenantID)).All(ctx)
		if err != nil {
			return nil, fmt.Errorf("list memberships: %w", err)
		}
		for _, m := range ms {
			for _, r := range m.Roles {
				set[r] = true
			}
		}
	}
	for _, r := range current.RequiredRoles {
		set[r] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		if strings.TrimSpace(r) != "" {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, nil
}

// platformOnlyMetadataKeys are tenant metadata keys that change what a token grants or what a
// sign-in must prove. A tenant's own admin, and a self-registered organisation, can never set
// them; the MFA keys are written only through the platform-owner MFA policy routes.
var platformOnlyMetadataKeys = map[string]bool{
	TenantMetadataMFAPolicy:          true,
	PlatformMetadataMFAPolicyDefault: true,
	"is_platform_owner":              true,
	"billing_mode":                   true,
	// is_demo exempts a whole tenant from what demo logins may not do; only the platform sets it.
	"is_demo": true,
	// The invite that created the organisation; set only by Register from a valid invite, so
	// nobody can burn another business's invitation by naming its id.
	MetaBusinessInvite: true,
}

// mfaPolicyMetadataKeys are written only through the MFA policy routes, by anyone.
var mfaPolicyMetadataKeys = map[string]bool{
	TenantMetadataMFAPolicy:          true,
	PlatformMetadataMFAPolicyDefault: true,
}

// IsPlatformOnlyMetadataKey reports whether a tenant metadata key may be set only by a platform
// owner.
func IsPlatformOnlyMetadataKey(k string) bool { return platformOnlyMetadataKeys[k] }

// IsMFAPolicyMetadataKey reports whether a tenant metadata key belongs to the MFA policy, which
// the generic tenant update never writes.
func IsMFAPolicyMetadataKey(k string) bool { return mfaPolicyMetadataKeys[k] }

// WithoutMFAPolicyMetadata returns meta without the MFA policy keys, for the public tenant lookups:
// which roles need a second factor is not public. Nil stays nil.
func WithoutMFAPolicyMetadata(meta map[string]any) map[string]any {
	if meta == nil {
		return nil
	}
	out := make(map[string]any, len(meta))
	for k, v := range meta {
		if !mfaPolicyMetadataKeys[k] {
			out[k] = v
		}
	}
	return out
}

// withoutRegistrantOnlyKeys drops profile keys a person may not set on their own account at
// registration: is_demo marks a shared demo login, which only the platform creates.
func withoutRegistrantOnlyKeys(profile map[string]any) map[string]any {
	if _, ok := profile["is_demo"]; !ok {
		return profile
	}
	out := copyMetadata(profile)
	delete(out, "is_demo")
	return out
}

// withoutPlatformOnlyMetadata returns meta without the platform-only keys (self-registration).
func withoutPlatformOnlyMetadata(meta map[string]any) map[string]any {
	out := make(map[string]any, len(meta))
	for k, v := range meta {
		if !platformOnlyMetadataKeys[k] {
			out[k] = v
		}
	}
	return out
}

func copyMetadata(meta map[string]any) map[string]any {
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	return out
}

// ── Session factors ──

// normalizeAMR drops empty and repeated methods, keeping the order the sign-in proved them in.
func normalizeAMR(amr []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(amr))
	for _, m := range amr {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

func hasMethod(amr []string, method string) bool {
	for _, m := range amr {
		if m == method {
			return true
		}
	}
	return false
}

// withSecondFactor adds totp and mfa to a first factor.
func withSecondFactor(first string) []string {
	return normalizeAMR([]string{first, AMRTOTP, AMRMFA})
}

// sessionFactors reads what a session proved from its metadata. A session from before the amr
// claim existed has none and is not enrolment-only.
func sessionFactors(sess *ent.Session) (amr []string, enrollmentOnly bool) {
	if sess == nil || sess.Metadata == nil {
		return nil, false
	}
	switch v := sess.Metadata[sessionMetadataAMR].(type) {
	case []any:
		for _, m := range v {
			if s, ok := m.(string); ok {
				amr = append(amr, s)
			}
		}
	case []string:
		amr = append(amr, v...)
	}
	enrollmentOnly, _ = sess.Metadata[sessionMetadataMFAEnrollment].(bool)
	return normalizeAMR(amr), enrollmentOnly
}

// sessionFactorsMetadata is the session metadata recording what the sign-in proved.
func sessionFactorsMetadata(existing map[string]any, amr []string, enrollmentOnly bool) map[string]any {
	meta := copyMetadata(existing)
	meta[sessionMetadataAMR] = normalizeAMR(amr)
	if enrollmentOnly {
		meta[sessionMetadataMFAEnrollment] = true
	} else {
		delete(meta, sessionMetadataMFAEnrollment)
	}
	return meta
}

// SessionFactorsMetadata exposes sessionFactorsMetadata to the OIDC code exchange, which creates
// its own session rows.
func SessionFactorsMetadata(amr []string, enrollmentOnly bool) map[string]any {
	return sessionFactorsMetadata(nil, amr, enrollmentOnly)
}

// gateSession applies the MFA policy at session issuance, the one place every sign-in path ends.
// A sign-in that proved a second factor passes. Otherwise a covered member with an authenticator
// is refused (the path should have asked for the code), and a covered member without one gets an
// enrolment-only session.
func (s *Service) gateSession(ctx context.Context, u *ent.User, t *ent.Tenant, amr []string) (enrollmentOnly bool, err error) {
	if u == nil || hasMethod(amr, AMRMFA) {
		return false, nil
	}
	st := s.mfaStatusFor(ctx, u.ID, t)
	switch {
	case !st.covered:
		return false, nil
	case st.hasAuthenticator:
		return false, ErrMFARequired
	default:
		return true, nil
	}
}

// gateRefresh is gateSession for a refresh. A lookup error comes back as an error to retry (the
// handler answers 5xx) instead of mfa_required, so a brief database error signs nobody out; the
// sign-in paths keep failing closed through gateSession.
func (s *Service) gateRefresh(ctx context.Context, u *ent.User, t *ent.Tenant, amr []string) (enrollmentOnly bool, err error) {
	if u == nil || hasMethod(amr, AMRMFA) {
		return false, nil
	}
	st, err := s.mfaStatusChecked(ctx, u.ID, t)
	if err != nil {
		return false, fmt.Errorf("mfa policy lookup: %w", err)
	}
	switch {
	case !st.covered:
		return false, nil
	case st.hasAuthenticator:
		return false, ErrMFARequired
	default:
		return true, nil
	}
}
