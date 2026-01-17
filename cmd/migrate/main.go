package main

import (
	"context"
	"log"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/bengobox/auth-api/internal/database"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	// Load only database config for migrations (no OAuth validation needed)
	dbCfg, err := config.LoadDatabaseOnly()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	client, err := database.NewClient(ctx, dbCfg)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer client.Close()

	if err := database.RunMigrations(ctx, client); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("migrations completed")
}
