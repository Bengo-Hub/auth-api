package main

import (
	"context"
	"log"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/joho/godotenv"
)

// migrationLockKey serializes migrations across pods: every replica runs this binary on start,
// and two concurrent ent schema diffs can race on the same DDL (the pos-api 2026-07-26 outage).
// Arbitrary but stable and unique per service ("AUTM", auth migrate).
const migrationLockKey int64 = 0x4155_544D

func main() {
	_ = godotenv.Load()

	// Load only database config for migrations (no OAuth validation needed)
	dbCfg, err := config.LoadDatabaseOnly()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if dbCfg.MigrateURL != "" {
		dbCfg.URL = dbCfg.MigrateURL
	} else {
		// A session advisory lock is only reliable on a direct connection. Through PgBouncer's
		// transaction pooling it can be orphaned on a server connection and block every later
		// migrate run (the hospital-api 2026-09-02 crash loop).
		log.Printf("WARNING: POSTGRES_MIGRATE_URL is not set; migrating through POSTGRES_URL")
	}
	// One connection: the advisory lock and every migration statement share the same session.
	dbCfg.MaxOpenConns = 1
	dbCfg.MaxIdleConns = 1

	ctx := context.Background()
	client, db, err := database.NewClient(ctx, dbCfg)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer client.Close()

	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		log.Fatalf("acquire migration lock: %v", err)
	}
	migrateErr := database.RunMigrations(ctx, client)
	if _, err := db.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLockKey); err != nil {
		log.Printf("release migration lock: %v", err)
	}
	if migrateErr != nil {
		client.Close()
		log.Fatalf("migrate: %v", migrateErr)
	}
	log.Println("migrations completed")
}
