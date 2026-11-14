// Command legal-draft saves an HTML file as a draft version of an effective-dated legal document
// through auth-api's admin endpoint (PUT /api/v1/admin/legal/documents/{type}/drafts/{version}).
// The draft stays private: the platform admin reads it on auth-ui's preview page and publishes it
// from there. Running it again replaces the draft's body until the draft is published.
//
// The admin's access token is read from AUTH_ADMIN_TOKEN, never from a flag, so it stays out of
// the shell history. The API base URL comes from --api or AUTH_API_URL; there is no default, so
// the command never reaches production by accident.
//
//	AUTH_API_URL=https://sso.codevertexafrica.com AUTH_ADMIN_TOKEN=... \
//	  go run ./cmd/legal-draft --file ../../marketflow/docs/autopilot-auto-publish-terms-v1.html --version 1 --dry-run
//
// --dry-run checks the file and prints what would be sent, without sending it.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	bodyRE    = regexp.MustCompile(`(?is)<body[^>]*>(.*)</body>`)
	scriptRE  = regexp.MustCompile(`(?is)<\s*(script|iframe|object|embed|style)\b`)
	versionRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	headingRE = regexp.MustCompile(`(?is)<h[1-3][^>]*>(.*?)</h[1-3]>`)
	tagRE     = regexp.MustCompile(`<[^>]+>`)
)

const maxHTMLBytes = 1 << 20

func main() {
	var (
		file     = flag.String("file", "", "HTML file with the document body (a full page is reduced to its <body>)")
		docType  = flag.String("type", "MARKETFLOW_AUTOPUBLISH_TERMS", "legal document type (effective-dated types only)")
		version  = flag.String("version", "", "version label, for example 1")
		effDate  = flag.String("effective-date", "", "proposed effective date YYYY-MM-DD (optional; set for real when publishing)")
		apiBase  = flag.String("api", os.Getenv("AUTH_API_URL"), "auth-api base URL (default AUTH_API_URL)")
		dryRun   = flag.Bool("dry-run", false, "check the file and print the request without sending it")
		timeoutS = flag.Int("timeout", 30, "request timeout in seconds")
	)
	flag.Parse()
	if err := run(*file, *docType, *version, *effDate, *apiBase, *dryRun, time.Duration(*timeoutS)*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "legal-draft:", err)
		os.Exit(1)
	}
}

func run(file, docType, version, effDate, apiBase string, dryRun bool, timeout time.Duration) error {
	if file == "" || version == "" {
		return errors.New("--file and --version are required")
	}
	if !versionRE.MatchString(version) {
		return fmt.Errorf("version %q: use 1 to 32 letters, digits, dots, dashes or underscores", version)
	}
	if effDate != "" {
		if _, err := time.Parse(time.DateOnly, effDate); err != nil {
			return fmt.Errorf("--effective-date must be YYYY-MM-DD: %w", err)
		}
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	html := documentBody(string(raw))
	if html == "" {
		return errors.New("the file has no content")
	}
	if len(html) > maxHTMLBytes {
		return fmt.Errorf("the body is %d bytes; auth-api accepts at most %d", len(html), maxHTMLBytes)
	}
	if scriptRE.MatchString(html) {
		return errors.New("the body has a script, style, frame or embed tag; auth-ui strips them, so remove them first")
	}

	base := strings.TrimRight(strings.TrimSpace(apiBase), "/")
	if base == "" {
		return errors.New("set --api or AUTH_API_URL")
	}
	endpoint := fmt.Sprintf("%s/api/v1/admin/legal/documents/%s/drafts/%s",
		base, url.PathEscape(docType), url.PathEscape(version))
	payload := map[string]string{"html_content": html}
	if effDate != "" {
		payload["effective_date"] = effDate
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	sum := sha256.Sum256([]byte(html))
	fmt.Printf("PUT %s\n", endpoint)
	fmt.Printf("body: %d bytes, sha256 %s\n", len(html), hex.EncodeToString(sum[:]))
	if effDate != "" {
		fmt.Printf("proposed effective date: %s\n", effDate)
	}
	headings := headingRE.FindAllStringSubmatch(html, -1)
	fmt.Printf("headings: %d\n", len(headings))
	for i, m := range headings {
		if i == 5 {
			fmt.Printf("  ... and %d more\n", len(headings)-5)
			break
		}
		fmt.Printf("  %s\n", strings.TrimSpace(tagRE.ReplaceAllString(m[1], "")))
	}
	if n := strings.Count(html, "OWNER TO CONFIRM"); n > 0 {
		fmt.Printf("note: %d [OWNER TO CONFIRM] marker(s) remain; resolve them before publishing\n", n)
	}
	if dryRun {
		fmt.Println("dry run: nothing sent")
		return nil
	}

	token := strings.TrimSpace(os.Getenv("AUTH_ADMIN_TOKEN"))
	if token == "" {
		return errors.New("set AUTH_ADMIN_TOKEN to a platform admin's access token")
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("auth-api answered %s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	fmt.Printf("saved (%s): %s\n", resp.Status, strings.TrimSpace(string(out)))
	return nil
}

// documentBody returns the part inside <body> for a full HTML page, or the whole text for a fragment.
func documentBody(s string) string {
	if m := bodyRE.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	return strings.TrimSpace(s)
}
