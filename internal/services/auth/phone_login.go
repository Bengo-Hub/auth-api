package auth

import (
	"context"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/userphone"
)

// Phone sign-in serves customer portals (Maskani owners and occupants) whose users often have no
// email. Only a phone already on file for an ACTIVE member of the named tenant can receive a code,
// so the flow can neither create accounts nor reveal which numbers exist.

// PhoneLoginTarget is the member a phone code is for.
type PhoneLoginTarget struct {
	User   *ent.User
	Tenant *ent.Tenant
	Phone  string
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
	up, err := s.entClient.UserPhone.Query().Where(userphone.PhoneEQ(phone)).WithUser().Only(ctx)
	if err != nil || up.Edges.User == nil {
		return miss("phone not on any account")
	}
	member, err := s.entClient.TenantMembership.Query().
		Where(tenantmembership.UserID(up.UserID), tenantmembership.TenantID(t.ID), tenantmembership.Status("active")).
		Exist(ctx)
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

// LoginWithPhoneOTP issues a session after the handler has verified the code. The phone is
// marked verified, since the member has just proven they hold it.
func (s *Service) LoginWithPhoneOTP(ctx context.Context, target *PhoneLoginTarget, clientID, ip, ua string) (*AuthResult, error) {
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
