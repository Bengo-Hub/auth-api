package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"

	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	dbURL := os.Getenv("AUTH_DB_URL")
	if dbURL == "" {
		log.Fatal("AUTH_DB_URL is required")
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

	// Connect to postgres database (default)
	defaultURL := "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	db, err := sql.Open("pgx", defaultURL)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("failed to ping postgres: %v", err)
	}

	// Create database
	query := fmt.Sprintf(`CREATE DATABASE "%s"`, dbName)
	_, err = db.ExecContext(ctx, query)
	if err != nil {
		log.Fatalf("failed to create database: %v", err)
	}

	fmt.Printf("✓ Database '%s' created successfully\n", dbName)
}
