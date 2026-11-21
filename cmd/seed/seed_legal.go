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
	// Repository revisions: each is published once, only while the version it follows is still
	// the newest one and no draft is open, so a type changed in the dashboard is left alone.
	for _, rev := range legal.Revisions {
		html, err := rev.HTML()
		if err != nil {
			return fmt.Errorf("%s v%s: %w", rev.DocType, rev.Version, err)
		}
		res, err := handlers.SeedRevision(ctx, client, rev.DocType, rev.Title, rev.Version, rev.After, rev.Summary, html, now)
		if err != nil {
			return fmt.Errorf("%s v%s: %w", rev.DocType, rev.Version, err)
		}
		log.Printf("  %s v%s: %s", rev.DocType, rev.Version, res)
	}
	return nil
}
