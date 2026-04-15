// Package main: cmd/cleanup — admin utility to delete a user by email.
//
// Use:
//   POSTGRES_URL=... go run ./cmd/cleanup -email user@example.com [-dry-run]
//
// Cascade deletes every referencing row before removing the user row,
// so a fresh registration with the same email succeeds without uniqueness
// collisions. Idempotent: silently exits 0 if the email doesn't exist.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	email := flag.String("email", "", "Email of the user to delete")
	dryRun := flag.Bool("dry-run", false, "Preview the deletion without committing")
	flag.Parse()

	if *email == "" {
		log.Fatal("-email is required")
	}

	dbURL := os.Getenv("POSTGRES_URL")
	if dbURL == "" {
		log.Fatal("POSTGRES_URL env var is required")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("ping: %v", err)
	}

	var userID string
	err = db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE email = $1`, *email).Scan(&userID)
	if err == sql.ErrNoRows {
		fmt.Printf("user %s not found - nothing to do\n", *email)
		return
	}
	if err != nil {
		log.Fatalf("lookup: %v", err)
	}
	fmt.Printf("Found user %s (id=%s)\n", *email, userID)

	// Rows that reference users(id). Order: children first, parent last.
	tables := []string{
		"tenant_memberships",
		"user_identities",
		"sessions",
		"password_reset_tokens",
		"mfa_backup_codes",
		"mfatotp_secrets",
		"authorization_codes",
	}

	if *dryRun {
		fmt.Println("Dry run — no changes committed.")
		for _, t := range tables {
			var n int
			_ = db.QueryRowContext(ctx,
				fmt.Sprintf("SELECT count(*) FROM %s WHERE user_id = $1", t), userID).Scan(&n)
			fmt.Printf("  %s: %d rows\n", t, n)
		}
		fmt.Println("  users: 1 row")
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Fatalf("begin tx: %v", err)
	}
	for _, t := range tables {
		res, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE user_id = $1", t), userID)
		if err != nil {
			_ = tx.Rollback()
			log.Fatalf("delete from %s: %v", t, err)
		}
		n, _ := res.RowsAffected()
		fmt.Printf("  %s: %d deleted\n", t, n)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		_ = tx.Rollback()
		log.Fatalf("delete user: %v", err)
	}
	n, _ := res.RowsAffected()
	fmt.Printf("  users: %d deleted\n", n)

	if err := tx.Commit(); err != nil {
		log.Fatalf("commit: %v", err)
	}
	fmt.Printf("✓ deleted %s\n", *email)
}
