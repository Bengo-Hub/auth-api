package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocumentBody(t *testing.T) {
	page := "<!doctype html><html><head><title>x</title></head><body class=\"a\">\n<h2>1. Terms</h2>\n</body></html>"
	if got := documentBody(page); got != "<h2>1. Terms</h2>" {
		t.Fatalf("full page: %q", got)
	}
	if got := documentBody("  <p>fragment</p> "); got != "<p>fragment</p>" {
		t.Fatalf("fragment: %q", got)
	}
}

func TestRun_DryRunSendsNothing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "terms.html")
	if err := os.WriteFile(file, []byte("<h2>1. About</h2><p>x</p>"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An unroutable API: a dry run must not try to reach it.
	if err := run(file, "MARKETFLOW_AUTOPUBLISH_TERMS", "1", "", "http://127.0.0.1:1", true, 0); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if err := run(file, "MARKETFLOW_AUTOPUBLISH_TERMS", "v 1", "", "http://127.0.0.1:1", true, 0); err == nil {
		t.Fatal("bad version accepted")
	}
	bad := filepath.Join(dir, "bad.html")
	_ = os.WriteFile(bad, []byte("<p>x</p><script>alert(1)</script>"), 0o600)
	if err := run(bad, "MARKETFLOW_AUTOPUBLISH_TERMS", "1", "", "http://127.0.0.1:1", true, 0); err == nil || !strings.Contains(err.Error(), "script") {
		t.Fatalf("script accepted: %v", err)
	}
}
