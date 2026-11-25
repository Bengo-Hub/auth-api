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

// Repository revisions carry the same heading ids, and the privacy revision has the TikTok
// sign-in section next to every anchor version 1 had.
func TestSeedRevisions_HeadingIDs(t *testing.T) {
	for _, rev := range legal.Revisions {
		html, err := rev.HTML()
		if err != nil {
			t.Fatalf("%s v%s: %v", rev.DocType, rev.Version, err)
		}
		if !isValidDocType(rev.DocType) || rev.Version == "" || rev.After == "" || rev.Summary == "" {
			t.Fatalf("incomplete revision %+v", rev)
		}
		for _, tag := range h2TagRE.FindAllString(html, -1) {
			if !strings.Contains(tag, `id="`) {
				t.Errorf("%s v%s: heading without an id: %s", rev.DocType, rev.Version, tag)
			}
		}
		if rev.DocType == "PRIVACY_POLICY" {
			for _, id := range []string{"google-signin", "tiktok", "tiktok-signin", "rights", "sub-processors"} {
				if !strings.Contains(html, `id="`+id+`"`) {
					t.Errorf("privacy v%s is missing #%s", rev.Version, id)
				}
			}
		}
	}
}

// A revision is published once after the version it follows, in force now, as a non-material
// change; it never edits that version and stays away from a type changed in the dashboard.
func TestSeedRevision(t *testing.T) {
	client := newLegalTestClient(t)
	ctx := context.Background()
	now := time.Now()
	const typ = DocTypeMarketFlowAutoPublishTerms

	if res, err := SeedRevision(ctx, client, typ, "Terms", "2", "1", "adds a part", "<h2 id=\"a\">v2</h2>", now); err != nil || res != SeedSkipped {
		t.Fatalf("no version 1 yet: res = %s, err = %v", res, err)
	}
	if res, err := SeedFirstVersion(ctx, client, typ, "Terms", "<h2 id=\"a\">v1</h2>", now.Add(-48*time.Hour)); err != nil || res != SeedPublished {
		t.Fatalf("v1: res = %s, err = %v", res, err)
	}
	res, err := SeedRevision(ctx, client, typ, "Terms", "2", "1", "adds a part", "<h2 id=\"a\">v2</h2>", now)
	if err != nil || res != SeedPublished {
		t.Fatalf("v2: res = %s, err = %v", res, err)
	}
	if res, err := SeedRevision(ctx, client, typ, "Terms", "2", "1", "adds a part", "<h2 id=\"a\">v2</h2>", now); err != nil || res != SeedSkipped {
		t.Fatalf("second run: res = %s, err = %v", res, err)
	}
	docs, err := client.LegalDocument.Query().Where(legaldocument.DocTypeEQ(legaldocument.DocType(typ))).All(ctx)
	if err != nil || len(docs) != 2 {
		t.Fatalf("docs = %d, err = %v", len(docs), err)
	}
	for _, d := range docs {
		switch d.Version {
		case "1":
			if d.HTMLContent != "<h2 id=\"a\">v1</h2>" || d.Status != legaldocument.StatusPublished {
				t.Errorf("version 1 changed: %+v", d)
			}
		case "2":
			if d.Status != legaldocument.StatusPublished || d.EffectiveDate.After(now) || d.Metadata["material"] != false ||
				d.Metadata["summary"] != "adds a part" {
				t.Errorf("version 2 not in force as a non-material change: %+v", d)
			}
		}
	}

	// The next revision follows version 2 although version 1 is still there, once.
	for i, want := range []SeedResult{SeedPublished, SeedSkipped} {
		if res, err := SeedRevision(ctx, client, typ, "Terms", "3", "2", "adds more", "<h2 id=\"a\">v3</h2>", now); err != nil || res != want {
			t.Fatalf("v3 run %d: res = %s, err = %v", i, res, err)
		}
	}
	if res, err := SeedRevision(ctx, client, typ, "Terms", "2", "1", "adds a part", "<h2 id=\"a\">v2</h2>", now); err != nil || res != SeedSkipped {
		t.Fatalf("v2 after v3: res = %s, err = %v", res, err)
	}

	// A type that moved on in the dashboard (an open draft) is left alone.
	const other = DocTypeCookiePolicy
	if _, err := SeedFirstVersion(ctx, client, other, "Cookies", "<h2 id=\"a\">v1</h2>", now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := insertDraft(ctx, client, other, "2026-12", "<h2 id=\"a\">dash</h2>", now, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if res, err := SeedRevision(ctx, client, other, "Cookies", "2", "1", "x", "<h2 id=\"a\">v2</h2>", now); err != nil || res != SeedSkipped {
		t.Fatalf("dashboard draft open: res = %s, err = %v", res, err)
	}
}
