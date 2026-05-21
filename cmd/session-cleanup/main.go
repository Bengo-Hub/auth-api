// Package main: cmd/session-cleanup — purges expired and revoked sessions.
//
// Run via Kubernetes CronJob (schedule: "0 * * * *") or manually:
//
//	POSTGRES_URL=... go run ./cmd/session-cleanup
//
// Deletes sessions where:
//   - expires_at < NOW()            (naturally expired)
//   - status = 'revoked'            (explicitly revoked by user or system)
//
// Keeps any session still active+unexpired so running sessions are unaffected.
// Idempotent: safe to run multiple times with no side effects.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/bengobox/auth-api/internal/ent/session"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	cfg, err := config.LoadForSeed()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	client, _, err := database.NewClient(ctx, cfg.Database)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer client.Close()

	now := time.Now()

	// Delete sessions that have naturally expired.
	expiredDeleted, err := client.Session.Delete().
		Where(session.ExpiresAtLT(now)).
		Exec(ctx)
	if err != nil {
		log.Fatalf("delete expired sessions: %v", err)
	}
	log.Printf("✓ Deleted %d expired session(s)", expiredDeleted)

	// Delete sessions that were explicitly revoked (already inactive, safe to purge).
	revokedDeleted, err := client.Session.Delete().
		Where(session.StatusEQ("revoked")).
		Exec(ctx)
	if err != nil {
		log.Fatalf("delete revoked sessions: %v", err)
	}
	log.Printf("✓ Deleted %d revoked session(s)", revokedDeleted)

	total := expiredDeleted + revokedDeleted
	if total == 0 {
		log.Printf("✅ No stale sessions to clean up — database is tidy")
	} else {
		log.Printf("✅ Session cleanup complete: %d total row(s) removed", total)
	}

	env := os.Getenv("SESSION_CLEANUP_LOG_ENV")
	if env == "" {
		env = "unknown"
	}
	log.Printf("ℹ️  environment=%s ran_at=%s", env, now.UTC().Format(time.RFC3339))
}
