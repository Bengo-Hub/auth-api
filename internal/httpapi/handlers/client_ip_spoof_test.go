package handlers

import (
	"net/http/httptest"
	"testing"
)

// The address recorded on sessions and checked by API key allowlists comes from the ingress (X-Real-IP,
// then the peer), never from a client-sent X-Forwarded-For.
func TestClientIPIgnoresAClientSentForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:51000"
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.7")
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q, want the peer address 203.0.113.7", got)
	}
	if got := getClientIP(r); got != "203.0.113.7" {
		t.Fatalf("getClientIP = %q, want the peer address 203.0.113.7 (an allowlist must not be passable by a header)", got)
	}

	// Behind the ingress, its X-Real-IP is the client.
	r.Header.Set("X-Real-IP", "192.0.2.44")
	if got := clientIP(r); got != "192.0.2.44" {
		t.Fatalf("clientIP = %q, want the ingress address 192.0.2.44", got)
	}
}
