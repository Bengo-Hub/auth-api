package auth

import (
	"testing"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
)

// A phone-code sign-in on an account with an authenticator app gets the same
// short-lived challenge as a social sign-in, bound to the person and tenant.
func TestPhoneMFAChallengeRoundTrip(t *testing.T) {
	s := &Service{cfg: &config.Config{}}
	s.cfg.Security.OAuthStateSecret = "test-secret-0123456789abcdef"
	uid := uuid.New()
	target := &PhoneLoginTarget{User: &ent.User{ID: uid}, Tenant: &ent.Tenant{Slug: "acme"}, Phone: "+254700000000"}

	challenge, err := s.PhoneMFAChallenge(target, "client-1")
	if err != nil || challenge == "" {
		t.Fatalf("challenge: %q %v", challenge, err)
	}
	p, err := s.decodeSocialMFAChallenge(challenge)
	if err != nil || p.UserID != uid.String() || p.TenantSlug != "acme" || p.ClientID != "client-1" {
		t.Fatalf("decoded: %+v %v", p, err)
	}
	if _, ttl, err := s.SocialMFAChallengeNonce(challenge); err != nil || ttl != socialMFAChallengeTTL {
		t.Fatalf("nonce: %v %v", ttl, err)
	}

	other := &Service{cfg: &config.Config{}}
	other.cfg.Security.OAuthStateSecret = "another-secret-0123456789abcd"
	if _, err := other.decodeSocialMFAChallenge(challenge); err == nil {
		t.Fatal("a challenge decoded with another secret")
	}
}
