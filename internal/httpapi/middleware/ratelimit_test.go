package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountKeyKeepsBody(t *testing.T) {
	body := `{"email":" User@Example.com ","password":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	if got := accountKey(req); got != "acct:user@example.com" {
		t.Fatalf("got %q", got)
	}
	rest, _ := io.ReadAll(req.Body)
	if string(rest) != body {
		t.Fatalf("handler must still see the full body, got %q", rest)
	}
	if accountKey(httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("not json"))) != "" {
		t.Fatal("non-JSON body must not produce an account key")
	}
}
