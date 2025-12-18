package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	dbURL := os.Getenv("AUTH_DB_URL")
	if dbURL == "" {
		// Fallback to AUTH_POSTGRES_URL
		dbURL = os.Getenv("AUTH_POSTGRES_URL")
	}
	if dbURL == "" {
		log.Fatal("AUTH_DB_URL or AUTH_POSTGRES_URL is required")
	}

	// Parse the URL to get the database name
	parsed, err := url.Parse(dbURL)
	if err != nil {
		log.Fatalf("failed to parse DB URL: %v", err)
	}

	dbName := parsed.Path[1:] // Remove leading /
	if dbName == "" {
		log.Fatal("no database name in URL")
	}

	// Decode URL-encoded database name (e.g., "auth%20service" -> "auth service")
	dbName, err = url.QueryUnescape(dbName)
	if err != nil {
		log.Fatalf("failed to unescape database name: %v", err)
	}

	// Create a connection URL for the postgres database (not the target db)
	// Reconstruct the URL but with "postgres" as the database
	postgreURL := reconstructURL(parsed, "postgres")

	log.Printf("Connecting to PostgreSQL server at %s:%s...\n", parsed.Hostname(), parsed.Port())

	// Retry logic for PostgreSQL server availability
	maxRetries := 30
	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err := sql.Open("pgx", postgreURL)
		if err != nil {
			log.Printf("Attempt %d: Failed to open connection: %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(2 * time.Second)
				continue
			}
			log.Fatalf("failed to open connection after %d attempts: %v", maxRetries, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = db.PingContext(ctx)
		cancel()

		if err != nil {
			log.Printf("Attempt %d: Failed to ping postgres: %v", attempt, err)
			db.Close()
			if attempt < maxRetries {
				time.Sleep(2 * time.Second)
				continue
			}
			log.Fatalf("failed to connect to postgres after %d attempts: %v", maxRetries, err)
		}

		// Connection successful
		ctx = context.Background()

		// Check if database already exists
		var exists bool
		query := fmt.Sprintf(`SELECT EXISTS(SELECT FROM pg_database WHERE datname = '%s')`, escapeSQLString(dbName))
		err = db.QueryRowContext(ctx, query).Scan(&exists)
		if err != nil {
			log.Fatalf("failed to check database: %v", err)
		}

		if exists {
			log.Printf("✓ Database '%s' already exists\n", dbName)
		} else {
			// Create database
			createQuery := fmt.Sprintf(`CREATE DATABASE "%s"`, dbName)
			_, err = db.ExecContext(ctx, createQuery)
			if err != nil {
				log.Fatalf("failed to create database: %v", err)
			}
			log.Printf("✓ Database '%s' created successfully\n", dbName)
		}

		db.Close()
		return
	}

	log.Fatal("failed to connect to postgres server")
}

// reconstructURL rebuilds the PostgreSQL connection URL with a different database
func reconstructURL(parsed *url.URL, database string) string {
	// Build the DSN manually using pgx format
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s/%s",
		parsed.User.Username(),
		url.QueryEscape(getPassword(parsed)),
		parsed.Host,
		database,
	)

	// Add query parameters if present (e.g., sslmode)
	if parsed.RawQuery != "" {
		dsn += "?" + parsed.RawQuery
	}

	return dsn
}

// getPassword extracts the password from the URL, handling cases where it might not be set
func getPassword(u *url.URL) string {
	if u.User == nil {
		return ""
	}
	password, _ := u.User.Password()
	return password
}

// escapeSQLString escapes a string for use in SQL queries (simple implementation)
func escapeSQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
