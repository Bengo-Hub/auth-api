package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/legaldocument"
)

// SeedVersion is the version label the seeder gives a type's first version.
const SeedVersion = "1"

// SeedResult says what SeedFirstVersion did for a type.
type SeedResult string

const (
	// SeedPublished means version 1 was created and published.
	SeedPublished SeedResult = "published"
	// SeedSkipped means the type already had a version, so nothing changed.
	SeedSkipped SeedResult = "skipped"
)

// SeedFirstVersion publishes html as version 1 of docType, in force from the start of today (UTC),
// only when the type has no version at all. It goes through the same insert and publish steps as
// the dashboard (insertDraft, publishDraftRow). The notice period does not apply, since nothing was
// published before, and no email goes out: the version is not a material change. A seeded draft
// left behind by an interrupted run is published on the next run; any other existing version means
// the type is managed from the dashboard and is left alone.
func SeedFirstVersion(ctx context.Context, client *ent.Client, docType, title, html string, now time.Time) (SeedResult, error) {
	docType = normalizeDocType(docType)
	if !isValidDocType(docType) {
		return "", fmt.Errorf("seed legal: unknown doc type %q", docType)
	}
	if strings.TrimSpace(html) == "" {
		return "", fmt.Errorf("seed legal: %s has no body", docType)
	}
	existing, err := client.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType))).
		All(ctx)
	if err != nil {
		return "", err
	}

	var draft *ent.LegalDocument
	switch {
	case len(existing) == 0:
		meta := map[string]any{"title": title, "summary": "First published version", "material": false,
			"updated_by": "seed", "seeded": true}
		draft, err = insertDraft(ctx, client, docType, SeedVersion, html, now, meta)
		if ent.IsConstraintError(err) {
			// Another seeder created it meanwhile.
			return SeedSkipped, nil
		}
		if err != nil {
			return "", err
		}
	case len(existing) == 1 && existing[0].Status == legaldocument.StatusDraft &&
		existing[0].Version == SeedVersion && existing[0].Metadata["seeded"] == true:
		draft = existing[0]
	default:
		return SeedSkipped, nil
	}

	return publishSeeded(ctx, client, draft, now)
}

// SeedRevision publishes html as version `version` of docType, following `after`, as a
// non-material change in force now. It runs only while `after` is the newest version of the type
// and no draft is open (or the open draft is this revision, left by an interrupted run); a type
// that moved on in the dashboard is left alone. The version it follows is never edited.
func SeedRevision(ctx context.Context, client *ent.Client, docType, title, version, after, summary, html string, now time.Time) (SeedResult, error) {
	docType = normalizeDocType(docType)
	if !isValidDocType(docType) {
		return "", fmt.Errorf("seed legal: unknown doc type %q", docType)
	}
	if strings.TrimSpace(html) == "" || version == "" || after == "" || version == after {
		return "", fmt.Errorf("seed legal: %s revision %q after %q is incomplete", docType, version, after)
	}
	existing, err := client.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(docType))).
		All(ctx)
	if err != nil {
		return "", err
	}
	var prev, draft *ent.LegalDocument
	for _, d := range existing {
		switch {
		case d.Version == after && d.Status == legaldocument.StatusPublished:
			prev = d
		case d.Version == version && d.Status == legaldocument.StatusDraft && d.Metadata["seeded"] == true:
			draft = d
		default:
			// Any other version (published later, or a dashboard draft) means the type is managed
			// from the dashboard now.
			return SeedSkipped, nil
		}
	}
	if prev == nil {
		return SeedSkipped, nil
	}
	if draft == nil {
		meta := map[string]any{"title": title, "summary": summary, "material": false, "updated_by": "seed", "seeded": true}
		draft, err = insertDraft(ctx, client, docType, version, html, now, meta)
		if ent.IsConstraintError(err) {
			return SeedSkipped, nil
		}
		if err != nil {
			return "", err
		}
	}
	return publishSeeded(ctx, client, draft, now)
}

// publishSeeded publishes a seeded draft as a non-material version in force from the start of
// today (UTC).
func publishSeeded(ctx context.Context, client *ent.Client, draft *ent.LegalDocument, now time.Time) (SeedResult, error) {
	u := now.UTC()
	effDate := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	meta := map[string]any{"published_by": "seed", "published_at": u.Format(time.RFC3339), "material": false}
	published, err := publishDraftRow(ctx, client, draft, effDate, meta)
	if err != nil {
		return "", err
	}
	if !published {
		return SeedSkipped, nil
	}
	return SeedPublished, nil
}
