package handlers

import (
	"context"
	"fmt"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/authorizationcode"
	"github.com/bengobox/auth-api/internal/ent/consentsession"
	"github.com/bengobox/auth-api/internal/ent/mfabackupcode"
	"github.com/bengobox/auth-api/internal/ent/mfasettings"
	"github.com/bengobox/auth-api/internal/ent/mfatotpsecret"
	"github.com/bengobox/auth-api/internal/ent/passwordresettoken"
	"github.com/bengobox/auth-api/internal/ent/referrallink"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/ent/tenantmembership"
	"github.com/bengobox/auth-api/internal/ent/useremail"
	"github.com/bengobox/auth-api/internal/ent/useridentity"
	"github.com/bengobox/auth-api/internal/ent/userphone"
	"github.com/bengobox/auth-api/internal/ent/webauthncredential"
	"github.com/bengobox/auth-api/internal/platform/outbox"
)

// deleteUserTx hard deletes a user and all their identity data inside tx: sessions, reset tokens,
// identities, authorization codes, MFA secrets and settings, WebAuthn credentials, emails, phones,
// consent grants, tenant memberships, then the user row. Login attempts and audit logs keep their
// user id (security and compliance records). Shared by AdminPurgeUser and the tenant purge.
func deleteUserTx(ctx context.Context, tx *ent.Tx, userID uuid.UUID) error {
	steps := []struct {
		name string
		run  func() error
	}{
		{"sessions", func() error { _, e := tx.Session.Delete().Where(session.UserID(userID)).Exec(ctx); return e }},
		{"password reset tokens", func() error {
			_, e := tx.PasswordResetToken.Delete().Where(passwordresettoken.UserID(userID)).Exec(ctx)
			return e
		}},
		{"identities", func() error { _, e := tx.UserIdentity.Delete().Where(useridentity.UserID(userID)).Exec(ctx); return e }},
		{"authorization codes", func() error {
			_, e := tx.AuthorizationCode.Delete().Where(authorizationcode.UserID(userID)).Exec(ctx)
			return e
		}},
		{"totp secrets", func() error {
			_, e := tx.MFATOTPSecret.Delete().Where(mfatotpsecret.UserID(userID)).Exec(ctx)
			return e
		}},
		{"backup codes", func() error {
			_, e := tx.MFABackupCode.Delete().Where(mfabackupcode.UserID(userID)).Exec(ctx)
			return e
		}},
		{"webauthn credentials", func() error {
			_, e := tx.WebAuthnCredential.Delete().Where(webauthncredential.UserID(userID)).Exec(ctx)
			return e
		}},
		{"emails", func() error { _, e := tx.UserEmail.Delete().Where(useremail.UserID(userID)).Exec(ctx); return e }},
		{"phones", func() error { _, e := tx.UserPhone.Delete().Where(userphone.UserID(userID)).Exec(ctx); return e }},
		{"mfa settings", func() error { _, e := tx.MFASettings.Delete().Where(mfasettings.UserID(userID)).Exec(ctx); return e }},
		{"consent sessions", func() error {
			_, e := tx.ConsentSession.Delete().Where(consentsession.UserID(userID)).Exec(ctx)
			return e
		}},
		{"memberships", func() error {
			_, e := tx.TenantMembership.Delete().Where(tenantmembership.UserID(userID)).Exec(ctx)
			return e
		}},
		{"user", func() error { return tx.User.DeleteOneID(userID).Exec(ctx) }},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			return fmt.Errorf("delete %s: %w", s.name, err)
		}
	}
	return nil
}

// purgeTenant hard deletes a tenant from the whole platform (user rule, 2026-11-03): its accounts
// that belong to no other tenant, every auth row carrying its tenant_id and the tenant row, then
// tenant.purge so every service deletes its data, and auth.user.deleted for the removed accounts.
// The platform tenant is refused. Safe to run again: each step only deletes what is left.
func (h *AdminHandler) purgeTenant(ctx context.Context, t *ent.Tenant, reason string) error {
	if t.Slug == platformTenantSlug {
		return fmt.Errorf("the platform tenant cannot be purged")
	}
	if v, ok := t.Metadata["is_platform_owner"].(bool); ok && v {
		return fmt.Errorf("a platform owner tenant cannot be purged")
	}
	if h.db == nil {
		return fmt.Errorf("tenant purge: database handle not configured")
	}

	// Accounts whose only membership is this tenant go with it.
	members, err := h.ent.TenantMembership.Query().Where(tenantmembership.TenantID(t.ID)).All(ctx)
	if err != nil {
		return fmt.Errorf("load members: %w", err)
	}
	type removed struct {
		id      uuid.UUID
		email   string
		primary string
	}
	var accounts []removed
	for _, m := range members {
		others, err := h.ent.TenantMembership.Query().
			Where(tenantmembership.UserID(m.UserID), tenantmembership.TenantIDNEQ(t.ID)).Exist(ctx)
		if err != nil {
			return fmt.Errorf("check other memberships: %w", err)
		}
		if others {
			continue
		}
		u, err := h.ent.User.Get(ctx, m.UserID)
		if ent.IsNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		accounts = append(accounts, removed{id: u.ID, email: u.Email, primary: u.PrimaryTenantID})
	}

	tx, err := h.ent.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	for _, a := range accounts {
		if err := deleteUserTx(ctx, tx, a.id); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("account %s: %w", a.email, err)
		}
	}
	if _, err := tx.Tenant.Update().Where(tenant.ManagedByResellerTenantID(t.ID)).ClearManagedByResellerTenantID().Save(ctx); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("clear reseller links: %w", err)
	}
	if _, err := tx.ReferralLink.Delete().Where(referrallink.ReferrerTenantID(t.ID)).Exec(ctx); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete referral links: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit accounts: %w", err)
	}

	// Every auth row with the tenant's tenant_id (memberships, outlets, domains, keys, ...), then
	// the tenant row, by the same schema-driven purger the services use.
	rows, err := (&sharedevents.TenantPurger{DB: h.db, Log: h.logger, Service: "auth"}).Purge(ctx, t.ID)
	if err != nil {
		return err
	}

	purge := sharedevents.NewTenantPurgeEvent(t.ID, t.Slug, reason)
	if err := outbox.Write(ctx, h.ent, t.ID, "tenant", t.ID, "purge", t.Slug, purge.Payload); err != nil {
		return fmt.Errorf("queue tenant.purge: %w", err)
	}
	for _, a := range accounts {
		var primary uuid.UUID
		if a.primary != "" {
			primary, _ = uuid.Parse(a.primary)
		}
		h.publishEvent(ctx, primary, "auth.user", a.id, "deleted", map[string]any{
			"user_id": a.id.String(), "email": a.email, "primary_tenant_id": a.primary,
			"tenant_ids": []string{t.ID.String()},
		})
	}
	h.logger.Warn("tenant purged", zap.String("tenant_id", t.ID.String()), zap.String("slug", t.Slug),
		zap.String("reason", reason), zap.Int("accounts", len(accounts)), zap.Int64("auth_rows", rows))
	return nil
}
