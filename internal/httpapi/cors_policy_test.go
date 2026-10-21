package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	httpware "github.com/Bengo-Hub/httpware"
)

func TestCORSPolicyOrigins(t *testing.T) {
	h := httpware.CORS(corsPolicy())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	cases := []struct {
		origin  string
		allowed bool
	}{
		{"https://accounts.codevertexafrica.com", true},
		{"https://erp.masterspace.co.ke", true},
		{"https://codevertexafrica.com", true},
		{"http://localhost:3000", true},
		{"https://evil.example.com", false},
		{"https://codevertexafrica.com.evil.example", false},
		{"http://accounts.codevertexafrica.com", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Origin", c.origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		got := rec.Header().Get("Access-Control-Allow-Origin") == c.origin
		if got != c.allowed {
			t.Errorf("origin %q allowed=%v, want %v", c.origin, got, c.allowed)
		}
	}
}
