package oidc

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/enttest"
)

func newOIDCTestClient(t *testing.T) *ent.Client {
	t.Helper()
	base := os.Getenv("TEST_POSTGRES_URL")
	if base == "" {
		base = "postgres://postgres:postgres@localhost:5432/auth?sslmode=disable"
	}
	db, err := sql.Open("postgres", base)
	if err != nil {
		t.Skipf("postgres: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("postgres unreachable: %v", err)
	}
	const schema = "ent_test_oidc"
	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE; CREATE SCHEMA " + schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	_ = db.Close()
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	client := enttest.Open(t, "postgres", base+sep+"search_path="+schema)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// Security audit 2026-11-10 (L2): the code was read as unconsumed and then marked consumed in a
// second step, so two exchanges racing on one code could both get tokens. Consuming is now one
// conditional update: only one caller wins.
func TestConsumeCodeOnce(t *testing.T) {
	client := newOIDCTestClient(t)
	ctx := context.Background()
	u := client.User.Create().SetEmail("u-" + uuid.NewString()[:8] + "@mail.test").SetStatus("active").SaveX(ctx)
	code := client.AuthorizationCode.Create().SetUserID(u.ID).SetClientID("c").SetRedirectURI("https://x/cb").
		SetScope("openid").SetCodeHash(uuid.NewString()).SetExpiresAt(time.Now().Add(time.Minute)).SaveX(ctx)

	if ok, err := consumeCode(ctx, client, code.ID); err != nil || !ok {
		t.Fatalf("first consume: %v %v", ok, err)
	}
	if ok, err := consumeCode(ctx, client, code.ID); err != nil || ok {
		t.Fatalf("second consume must lose: %v %v", ok, err)
	}
}
