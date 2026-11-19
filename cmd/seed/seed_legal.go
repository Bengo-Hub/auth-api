package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/httpapi/handlers"
	"github.com/bengobox/auth-api/internal/seed/legal"
)

// seedLegalDocuments publishes version 1 of each document in internal/seed/legal whose type has
// no version yet. A type that already has a version is left as it is, so running the seeder again
// changes nothing and never overwrites what was published from the dashboard.
func seedLegalDocuments(ctx context.Context, client *ent.Client) error {
	log.Println("Seeding legal documents...")
	now := time.Now()
	for _, doc := range legal.Documents {
		html, err := doc.HTML()
		if err != nil {
			return fmt.Errorf("%s: %w", doc.DocType, err)
		}
		res, err := handlers.SeedFirstVersion(ctx, client, doc.DocType, doc.Title, html, now)
		if err != nil {
			return fmt.Errorf("%s: %w", doc.DocType, err)
		}
		log.Printf("  %s: %s", doc.DocType, res)
	}
	return nil
}
