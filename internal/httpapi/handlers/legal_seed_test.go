package handlers

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bengobox/auth-api/internal/ent/legaldocument"
	"github.com/bengobox/auth-api/internal/seed/legal"
)

var h2TagRE = regexp.MustCompile(`<h2[^>]*>`)

// Every seeded body has an id on each <h2> (auth-ui builds the Contents list from them), and the
// anchors other pages and emails link to are present.
func TestSeedLegalDocuments_HeadingIDs(t *testing.T) {
	want := map[string][]string{
		"PRIVACY_POLICY":   {"google-ads", "google-signin", "meta-data", "google-calendar", "youtube", "tiktok", "google-limited-use", "sub-processors", "retention", "rights"},
		"TERMS_OF_SERVICE": {"acceptable-use", "prohibited", "api-usage", "youtube", "tiktok", "termination"},
		"DATA_REQUESTS":    {"meta", "youtube-tiktok"},
	}
	for _, doc := range legal.Documents {
		html, err := doc.HTML()
		if err != nil {
			t.Fatalf("%s: %v", doc.DocType, err)
		}
		if !isValidDocType(doc.DocType) {
			t.Fatalf("%s is not a known doc type", doc.DocType)
		}
		tags := h2TagRE.FindAllString(html, -1)
		if len(tags) < 2 {
			t.Fatalf("%s has %d <h2> headings", doc.DocType, len(tags))
		}
		for _, tag := range tags {
			if !strings.Contains(tag, `id="`) {
				t.Errorf("%s: heading without an id: %s", doc.DocType, tag)
			}
		}
		if scriptRE := regexp.MustCompile(`(?i)<\s*(script|iframe|object|embed|style)\b`); scriptRE.MatchString(html) {
			t.Errorf("%s has a tag auth-ui strips", doc.DocType)
		}
		for _, id := range want[doc.DocType] {
			if !strings.Contains(html, `id="`+id+`"`) {
				t.Errorf("%s is missing the #%s anchor", doc.DocType, id)
			}
		}
	}
}

// The seeder publishes version 1 once per type; a second run changes nothing, and a type that
// already has a version from the dashboard is left alone.
func TestSeedFirstVersion_Idempotent(t *testing.T) {
	client := newLegalTestClient(t)
	ctx := context.Background()
	now := time.Now()

	// A version published from the dashboard before the seeder ever ran.
	seedTermsVersion(t, client, "2026-11", now.Add(-time.Hour))

	run := func() map[string]SeedResult {
		out := map[string]SeedResult{}
		for _, doc := range legal.Documents {
			html, err := doc.HTML()
			if err != nil {
				t.Fatal(err)
			}
			res, err := SeedFirstVersion(ctx, client, doc.DocType, doc.Title, html, now)
			if err != nil {
				t.Fatalf("seed %s: %v", doc.DocType, err)
			}
			out[doc.DocType] = res
		}
		return out
	}

	first := run()
	for _, doc := range legal.Documents {
		want := SeedPublished
		if doc.DocType == DocTypeMarketFlowAutoPublishTerms {
			want = SeedSkipped
		}
		if first[doc.DocType] != want {
			t.Errorf("first run %s = %s, want %s", doc.DocType, first[doc.DocType], want)
		}
	}
	countBefore, _ := client.LegalDocument.Query().Count(ctx)

	second := run()
	for typ, res := range second {
		if res != SeedSkipped {
			t.Errorf("second run %s = %s, want skipped", typ, res)
		}
	}
	if countAfter, _ := client.LegalDocument.Query().Count(ctx); countAfter != countBefore {
		t.Fatalf("second run changed the row count: %d then %d", countBefore, countAfter)
	}

	// The seeded version is published, in force now and readable through the public timeline.
	current, upcoming, err := docTimeline(ctx, client, DocTypePrivacyPolicy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.Version != SeedVersion || upcoming != nil {
		t.Fatalf("privacy timeline current=%v upcoming=%v", current, upcoming)
	}
	if current.Status != legaldocument.StatusPublished || docMaterial(current) || current.Metadata["published_by"] != "seed" {
		t.Fatalf("seeded row = %+v", current)
	}
	if !strings.Contains(current.HTMLContent, `id="google-signin"`) {
		t.Fatal("seeded body is not the embedded privacy policy")
	}

	// The autopilot terms kept the dashboard version only.
	n, _ := client.LegalDocument.Query().
		Where(legaldocument.DocTypeEQ(legaldocument.DocType(DocTypeMarketFlowAutoPublishTerms))).Count(ctx)
	if n != 1 {
		t.Fatalf("autopilot terms have %d versions, want the 1 from the dashboard", n)
	}
}

// A seeded draft left by an interrupted run is published on the next run.
func TestSeedFirstVersion_FinishesInterruptedRun(t *testing.T) {
	client := newLegalTestClient(t)
	ctx := context.Background()
	now := time.Now()
	if _, err := insertDraft(ctx, client, DocTypeCookiePolicy, SeedVersion, "<h2 id=\"what\">x</h2>", now,
		map[string]any{"seeded": true}); err != nil {
		t.Fatal(err)
	}
	res, err := SeedFirstVersion(ctx, client, DocTypeCookiePolicy, "Cookie Policy", "<h2 id=\"what\">x</h2>", now)
	if err != nil || res != SeedPublished {
		t.Fatalf("res = %s, err = %v", res, err)
	}
	doc, err := client.LegalDocument.Query().Where(legaldocument.DocTypeEQ(legaldocument.DocTypeCOOKIE_POLICY)).Only(ctx)
	if err != nil || doc.Status != legaldocument.StatusPublished {
		t.Fatalf("doc = %+v, err = %v", doc, err)
	}
}
