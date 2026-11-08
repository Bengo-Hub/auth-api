package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/services/sessionlimit"
)

func TestRefreshTTLFor(t *testing.T) {
	cfg := config.TokenConfig{
		RefreshTokenTTL:     24 * time.Hour,
		LongRefreshTokenTTL: 168 * time.Hour,
		LongRefreshClients:  []string{"rider-app", "hadia-ui"},
	}
	for client, want := range map[string]time.Duration{
		"treasury-ui": 24 * time.Hour,
		"pos-ui":      24 * time.Hour,
		"":            24 * time.Hour,
		"rider-app":   168 * time.Hour,
		"hadia-ui":    168 * time.Hour,
	} {
		if got := cfg.RefreshTTLFor(client); got != want {
			t.Errorf("%q: got %v, want %v", client, got, want)
		}
	}
}

// The limit keeps the most recently used sessions, per person and per app, and leaves every other
// person and app alone.
func TestSessionLimitKeepsMostRecentlyUsedPerPersonAndApp(t *testing.T) {
	_, client, _ := newPhoneSignupTestService(t)
	ctx := context.Background()
	newUser := func(prefix string) *ent.User {
		u, err := client.User.Create().SetEmail(prefix + "-" + uuid.NewString()[:8] + "@mail.test").SetStatus("active").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	start := time.Now().Add(-time.Hour)
	add := func(u *ent.User, app string, age int) *ent.Session {
		s, err := client.Session.Create().SetUserID(u.ID).SetClientID(app).SetRefreshTokenHash(uuid.NewString()).
			SetExpiresAt(time.Now().Add(time.Hour)).SetUpdatedAt(start.Add(-time.Duration(age) * time.Minute)).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	status := func(s *ent.Session) *ent.Session {
		got, err := client.Session.Get(ctx, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	alice, bob := newUser("alice"), newUser("bob")
	var sessions []*ent.Session
	for age := 0; age < 7; age++ { // age 0 is the most recently used
		sessions = append(sessions, add(alice, "pos-ui", age))
	}
	otherApp := add(alice, "treasury-ui", 100)
	otherPerson := add(bob, "pos-ui", 100)

	ended, err := sessionlimit.Enforce(ctx, client, alice.ID, "pos-ui", 5)
	if err != nil || ended != 2 {
		t.Fatalf("ended %d, err %v; want 2", ended, err)
	}
	for age, s := range sessions {
		got := status(s)
		if age < 5 && got.Status != "active" {
			t.Errorf("age %d should be kept, is %s", age, got.Status)
		}
		if age >= 5 && (got.Status != "revoked" || got.RevocationReason != sessionlimit.RevocationReason || got.RevokedAt.IsZero()) {
			t.Errorf("age %d should be ended by the limit: %+v", age, got)
		}
	}
	if status(otherApp).Status != "active" || status(otherPerson).Status != "active" {
		t.Error("another app or person was affected")
	}

	if again, err := sessionlimit.Enforce(ctx, client, alice.ID, "pos-ui", 5); err != nil || again != 0 {
		t.Errorf("second run ended %d, err %v; want 0", again, err)
	}
	for age := 0; age < 3; age++ {
		add(bob, "pos-ui", age)
	}
	if off, err := sessionlimit.Enforce(ctx, client, bob.ID, "pos-ui", 0); err != nil || off != 0 {
		t.Errorf("a limit of zero must do nothing: %d %v", off, err)
	}
}
