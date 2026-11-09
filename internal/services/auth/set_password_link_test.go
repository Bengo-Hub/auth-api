package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent/passwordresettoken"
	"github.com/bengobox/auth-api/internal/password"
)

// An invite's set-password link (owner, 10 November 2026): one-time, 72 hours, on the tenant's own
// app path, and setting a password from it ends the pending "change your temporary password".
func TestSetPasswordLink(t *testing.T) {
	s, client, _ := newPhoneSignupTestService(t)
	s.hasher = password.NewHasher(config.SecurityConfig{})
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	tn, err := client.Tenant.Create().SetName("hadia").SetSlug("hadia-" + suffix).SetStatus("active").
		SetMetadata(map[string]any{"app_url": "https://staging.hadiafrica.com"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.User.Create().SetEmail("staff-" + suffix + "@mail.test").SetStatus("active").
		SetProfile(map[string]any{"must_change_password": true, "name": "Wanjiru"}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.TenantMembership.Create().SetUserID(u.ID).SetTenantID(tn.ID).SetRoles([]string{"hadia_staff"}).SetStatus("active").Save(ctx); err != nil {
		t.Fatal(err)
	}

	link, err := s.IssueSetPasswordLink(ctx, u.ID, tn.Slug, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil || parsed.Host != "staging.hadiafrica.com" || parsed.Path != "/"+tn.Slug+"/auth/reset-password" {
		t.Fatalf("link = %s", link)
	}
	tok := parsed.Query().Get("token")
	row, err := client.PasswordResetToken.Query().Where(passwordresettoken.TokenHashEQ(hashToken(tok))).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(row.ExpiresAt); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("link lasts %s, want 72 hours", d)
	}

	if err := s.ConfirmPasswordReset(ctx, PasswordResetConfirmInput{Token: tok, NewPassword: "Kiondo!Basket2026x"}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	after, err := client.User.Get(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, pending := after.Profile["must_change_password"]; pending || after.Profile["name"] != "Wanjiru" {
		t.Fatalf("profile after = %v", after.Profile)
	}
	if err := s.ConfirmPasswordReset(ctx, PasswordResetConfirmInput{Token: tok, NewPassword: "Another!Pass2026y"}); !errors.Is(err, ErrPasswordResetTokenInvalid) {
		t.Fatalf("a used link worked again: %v", err)
	}
}
