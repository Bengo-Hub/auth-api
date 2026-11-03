package auth

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/userphone"
)

// Phone sign-in serves customer portals (Maskani owners and occupants, Hadia registry owners) whose
// users often have no email. By default only a phone already on file for an ACTIVE member of the
// named tenant can receive a code, so the flow can neither create accounts nor reveal which numbers
// exist. A tenant that opts in to phone self-signup (phone_signup.go) also accepts a phone that is
// on no account, and a verified phone on an account that is not yet in the tenant; the account and
// membership are created only after the code is verified, and every answer stays the same.

// PhoneLoginTarget is the member a phone code is for.
type PhoneLoginTarget struct {
	// User is nil for a phone that signs up (no account holds it yet).
	User   *ent.User
	Tenant *ent.Tenant
	Phone  string
	// Signup is set when the tenant's phone self-signup admits the phone: the membership (and,
	// with User nil, the account) is created once the code is verified.
	Signup *PhoneSignupPolicy
}

// FindPhoneLoginTarget resolves an E.164 phone to an active member of the tenant. Returns
// ErrInvalidCredentials for every miss so callers cannot tell the cases apart.
func (s *Service) FindPhoneLoginTarget(ctx context.Context, tenantSlug, phone string) (*PhoneLoginTarget, error) {
	if strings.TrimSpace(tenantSlug) == "" || phone == "" {
		return nil, ErrInvalidCredentials
	}
	// The caller answers the same either way, so the reason is only logged, with the phone masked.
	miss := func(reason string) (*PhoneLoginTarget, error) {
		s.logger.Info("phone login: no code sent", zap.String("tenant", tenantSlug),
			zap.String("phone", maskPhone(phone)), zap.String("reason", reason))
		return nil, ErrInvalidCredentials
	}
	t, err := s.GetTenantBySlug(ctx, tenantSlug)
	if err != nil || t == nil || t.Status != "active" {
		return miss("tenant not found or inactive")
	}
	policy, signupOn := TenantPhoneSignupPolicy(t)
	up, err := s.entClient.UserPhone.Query().Where(userphone.PhoneEQ(phone)).WithUser().Only(ctx)
	if ent.IsNotFound(err) && signupOn {
		return signupTarget(t, phone, policy, nil), nil
	}
	if err != nil || up.Edges.User == nil {
		return miss("phone not on any account")
	}
	member, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(up.UserID), tenantmembership.TenantID(t.ID), tenantmembership.Status("active")).
		Exist(ctx)
	if err == nil && !member && signupOn && up.IsVerified && UserCanSignIn(up.Edges.User.Status) {
		// A proven phone on an account from another tenant joins this one. An unverified phone
		// does not: proving it would not prove the account is the caller's. A membership in any
		// other status (suspended, removed) is never re-activated by a code.
		if any, aErr := s.hasAnyMembership(ctx, up.UserID, t.ID); aErr == nil && !any {
			return signupTarget(t, phone, policy, up.Edges.User), nil
		}
	}
	if err != nil || !member {
		return miss("account holding the phone is not an active member of the tenant")
	}
	if !UserCanSignIn(up.Edges.User.Status) {
		return miss("account cannot sign in: " + up.Edges.User.Status)
	}
	return &PhoneLoginTarget{User: up.Edges.User, Tenant: t, Phone: phone}, nil
}

// maskPhone keeps the last three digits, enough to match a support report without logging the number.
func maskPhone(p string) string {
	if len(p) <= 3 {
		return "***"
	}
	return strings.Repeat("*", len(p)-3) + p[len(p)-3:]
}

// PhoneOTPChannelWhatsApp asks for the code on WhatsApp even when the member has an email.
const PhoneOTPChannelWhatsApp = "whatsapp"

// SendPhoneOTP publishes the code for notifications-api to deliver (the same otp.requested event as
// the email code, with purpose phone_login). Email comes first when the member has a real address,
// since it needs no approved WhatsApp template; WhatsApp carries it when there is no email or the
// member asks for it. Platform sender, so a tenant's own messaging plan never blocks a sign-in.
func (s *Service) SendPhoneOTP(ctx context.Context, target *PhoneLoginTarget, otp string, ttl time.Duration, channel string) {
	if target.User == nil {
		s.sendSignupPhoneOTP(ctx, target, otp, ttl)
		return
	}
	payload := map[string]any{
		"user_id":     target.User.ID.String(),
		"tenant_id":   target.Tenant.ID.String(),
		"phone":       target.Phone,
		"otp":         otp,
		"ttl_minutes": int(ttl.Minutes()),
		"brand_name":  target.Tenant.Name,
		"purpose":     "phone_login",
		"channel":     PhoneOTPChannelWhatsApp,
	}
	if email := strings.TrimSpace(target.User.Email); channel != PhoneOTPChannelWhatsApp && email != "" && !isPlaceholderEmail(email) {
		payload["login_email"], payload["channel"] = email, "email"
	}
	s.publishEvent(ctx, target.Tenant.ID, "auth.user", target.User.ID, "otp.requested", payload)
}

// sendSignupPhoneOTP sends the code to a phone no account holds yet: WhatsApp only (there is no
// email to use), a fresh aggregate id per send so notifications-api never swallows a resend.
func (s *Service) sendSignupPhoneOTP(ctx context.Context, target *PhoneLoginTarget, otp string, ttl time.Duration) {
	s.publishEvent(ctx, target.Tenant.ID, "auth.user", uuid.New(), "otp.requested", map[string]any{
		"user_id":     "",
		"tenant_id":   target.Tenant.ID.String(),
		"phone":       target.Phone,
		"otp":         otp,
		"ttl_minutes": int(ttl.Minutes()),
		"brand_name":  target.Tenant.Name,
		"purpose":     "phone_login",
		"signup":      true,
		"channel":     PhoneOTPChannelWhatsApp,
	})
}

// LoginWithPhoneOTP issues a session after the handler has verified the code. The phone is
// marked verified, since the member has just proven they hold it. A signup target first becomes
// a member (and, when needed, an account), so its token carries the new membership's services.
func (s *Service) LoginWithPhoneOTP(ctx context.Context, target *PhoneLoginTarget, clientID, ip, ua string) (*AuthResult, error) {
	if target.Signup != nil {
		if err := s.completePhoneSignup(ctx, target); err != nil {
			return nil, err
		}
	}
	now := time.Now()
	_ = s.entClient.UserPhone.Update().
		Where(userphone.PhoneEQ(target.Phone), userphone.UserIDEQ(target.User.ID), userphone.IsVerifiedEQ(false)).
		SetIsVerified(true).SetVerifiedAt(now).Exec(ctx)
	return s.issueSession(ctx, issueSessionInput{
		User:      target.User,
		Tenant:    target.Tenant,
		ClientID:  clientID,
		IPAddress: ip,
		UserAgent: ua,
	})
}
