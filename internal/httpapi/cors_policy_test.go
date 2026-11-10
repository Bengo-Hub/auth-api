package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	httpware "github.com/Bengo-Hub/httpware"
)

func TestCORSPolicyOrigins(t *testing.T) {
	h := httpware.CORS(corsPolicy(false))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	cases := []struct {
		origin  string
		allowed bool
	}{
		{"https://accounts.codevertexafrica.com", true},
		{"https://erp.masterspace.co.ke", true},
		{"https://codevertexafrica.com", true},
		{"http://localhost:3000", false}, // development only, see below
		{"https://pos.codevertexafrica.com", true},
		{"https://marketflow.codevertexafrica.com", true},
		{"https://www.codevertexafrica.com", true},
		{"https://webmail.codevertexafrica.com", false}, // renders incoming email HTML (audit M3)
		{"https://argocd.codevertexafrica.com", false},
		{"https://nats.codevertexafrica.com", false},
		{"https://unknown.codevertexafrica.com", false},
		{"https://evil.example.com", false},
		{"https://codevertexafrica.com.evil.example", false},
		{"http://accounts.codevertexafrica.com", false},
		{"https://alphachinamarket.co.ke", false}, // only when configured, see below
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

func TestCORSPolicyTenantHosts(t *testing.T) {
	h := httpware.CORS(corsPolicy(false, "alphachinamarket.co.ke", " urbaneats.theurbanloftcafe.com"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for origin, want := range map[string]bool{
		"https://alphachinamarket.co.ke":          true,
		"https://urbaneats.theurbanloftcafe.com":  true,
		"http://alphachinamarket.co.ke":           false,
		"https://alphachinamarket.co.ke.evil.com": false,
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin") == origin; got != want {
			t.Errorf("origin %q allowed=%v, want %v", origin, got, want)
		}
	}
}

// Audit M3: localhost origins only in development.
func TestCORSPolicyDevOrigins(t *testing.T) {
	h := httpware.CORS(corsPolicy(true))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Fatal("development keeps localhost")
	}
}
