package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/config"
)

func newTestTokenService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	privPath, pubPath := filepath.Join(dir, "priv.pem"), filepath.Join(dir, "pub.pem")
	_ = os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	_ = os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600)
	s, err := NewService(config.TokenConfig{Issuer: "test", Audience: "codevertex", PrivateKeyPath: privPath, PublicKeyPath: pubPath,
		AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The amr list reaches the token as given.
func TestMintCarriesAMR(t *testing.T) {
	s := newTestTokenService(t)
	signed, _, err := s.MintAccessToken(AccessTokenInput{UserID: uuid.New(), SessionID: uuid.New(), AMR: []string{"pwd", "totp", "mfa"}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.AMR, ",") != "pwd,totp,mfa" || !c.HasAMR("mfa") || c.MFAEnrollmentRequired {
		t.Fatalf("claims %+v", c)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "codevertex" {
		t.Fatalf("audience %v", c.Audience)
	}
}

// Whatever a caller puts on an enrolment-only token, it is minted with identity alone: no roles,
// permissions, services, outlets, plan or platform-owner status, and only the enrolment audience.
func TestEnrollmentOnlyTokenGrantsNothing(t *testing.T) {
	s := newTestTokenService(t)
	tid := uuid.New()
	expires := time.Now().Add(24 * time.Hour)
	signed, _, err := s.MintAccessToken(AccessTokenInput{
		UserID: uuid.New(), SessionID: uuid.New(), TenantID: &tid, TenantSlug: "hadia", Email: "staff@example.com",
		Roles: []string{"hadia_admin"}, Permissions: []string{"hadia.payouts.approve"}, IsPlatformOwner: true,
		UserServices: []string{"*"}, OutletIDs: []string{uuid.NewString()}, OutletID: uuid.NewString(),
		SubscriptionPlan: "PRO", SubscriptionFeatures: []string{"x"}, ActiveServiceTags: []string{"hadia"},
		ActiveProducts: []string{"hadia"}, SubscriptionExpires: &expires, SubscriptionExempt: true, BillingMode: "service_charge",
		Audience: []string{"hadia-ui", "codevertex"}, AMR: []string{"pwd"}, MFAEnrollmentRequired: true, IsDemo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !c.MFAEnrollmentRequired || strings.Join(c.AMR, ",") != "pwd" || c.TenantSlug != "hadia" || c.Email != "staff@example.com" || !c.IsDemo {
		t.Fatalf("identity lost: %+v", c)
	}
	if len(c.Roles) != 0 || len(c.Permissions) != 0 || c.IsPlatformOwner || c.UserServices != nil || len(c.OutletIDs) != 0 ||
		c.OutletID != "" || c.SubscriptionPlan != "" || len(c.SubscriptionFeatures) != 0 || len(c.ActiveServiceTags) != 0 ||
		len(c.ActiveProducts) != 0 || c.SubscriptionExpires != nil || c.SubscriptionExempt || c.BillingMode != "" {
		t.Fatalf("an enrolment-only token grants: %+v", c)
	}
	if len(c.Audience) != 1 || c.Audience[0] != AudienceMFAEnrollment {
		t.Fatalf("audience %v, want only %s", c.Audience, AudienceMFAEnrollment)
	}
}
