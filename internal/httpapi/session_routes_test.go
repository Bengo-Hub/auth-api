package httpapi

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/bengobox/auth-api/internal/httpapi/handlers"
)

// The cookie session CSRF check uses the CORS policy's own origin matching.
func TestCORSOriginAllowedMatchesThePolicy(t *testing.T) {
	allowed := corsOriginAllowed(corsPolicy(false, "alphachinamarket.co.ke"))
	for origin, want := range map[string]bool{
		"https://pos.codevertexafrica.com":          true,
		"https://marketflow.codevertexafrica.com":   true,
		"https://erp.masterspace.co.ke":             true,
		"https://alphachinamarket.co.ke":            true,
		"https://webmail.codevertexafrica.com":      false,
		"https://evil.example.com":                  false,
		"https://codevertexafrica.com.evil.example": false,
		"http://pos.codevertexafrica.com":           false,
		"http://localhost:3000":                     false,
		"null":                                      false,
		"":                                          false,
	} {
		if got := allowed(origin); got != want {
			t.Errorf("origin %q allowed=%v, want %v", origin, got, want)
		}
	}
}

// The mounted /api/v1/session routes refuse a foreign origin or a missing header with 403, let an
// allowlisted origin through, and the preflight for the custom header passes.
func TestSessionRoutesCSRF(t *testing.T) {
	swagger, err := handlers.NewSwaggerHandler(nil)
	if err != nil {
		t.Fatal(err)
	}
	pass := func(next http.Handler) http.Handler { return next }
	reached := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	// Every route mounts as in production (see TestOpenAPIPathsExist); the session ones answer 200.
	var ah AuthHandlers
	fields := reflect.ValueOf(&ah).Elem()
	noop := reflect.ValueOf(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for i := 0; i < fields.NumField(); i++ {
		if fields.Field(i).Type() == noop.Type() {
			fields.Field(i).Set(noop)
		}
	}
	ah.SessionStart, ah.SessionRefresh, ah.SessionEnd = reached, reached, reached
	r := NewRouter(RouterDeps{
		HealthHandler:         func(http.ResponseWriter, *http.Request) {},
		DomainHandler:         &handlers.DomainHandler{},
		SwaggerHandler:        swagger,
		AuthHandlers:          ah,
		UserHandler:           &handlers.UserHandler{},
		LegalHandler:          &handlers.LegalHandler{},
		ResellerHandler:       &handlers.ResellerHandler{},
		ResellerPortalHandler: &handlers.ResellerPortalHandler{},
		ReferralLinkHandler:   &handlers.ReferralLinkHandler{},
		EquityPortalHandler:   &handlers.EquityPortalHandler{},
		OutletHandler:         &handlers.OutletHandler{},
		RBACHandler:           &handlers.RBACHandler{},
		K8sMonitorHandler:     &handlers.K8sMonitorHandler{},
		SealedSecretsHandler:  &handlers.SealedSecretsHandler{},
		InternalServiceKey:    "test-key",
		RequireAuthHandler:    pass,
		TryAuthHandler:        pass,
		RateLimitLogin:        pass,
		RateLimitToken:        pass,
		RateLimitSensitive:    pass,
		EquityPortalAuth:      pass,
	})
	cases := []struct {
		name   string
		path   string
		origin string
		xrw    string
		status int
	}{
		{"refresh from an app", "/api/v1/session/refresh", "https://pos.codevertexafrica.com", "codevertex", http.StatusOK},
		{"start from an app", "/api/v1/session/start", "https://marketflow.codevertexafrica.com", "codevertex", http.StatusOK},
		{"end from an app", "/api/v1/session/end", "https://accounts.codevertexafrica.com", "codevertex", http.StatusOK},
		{"refresh from webmail", "/api/v1/session/refresh", "https://webmail.codevertexafrica.com", "codevertex", http.StatusForbidden},
		{"refresh from a foreign site", "/api/v1/session/refresh", "https://evil.example.com", "codevertex", http.StatusForbidden},
		{"refresh without the header", "/api/v1/session/refresh", "https://pos.codevertexafrica.com", "", http.StatusForbidden},
		{"end without Origin", "/api/v1/session/end", "", "codevertex", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, c.path, nil)
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			if c.xrw != "" {
				req.Header.Set("X-Requested-With", c.xrw)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != c.status {
				t.Fatalf("%d %s, want %d", rec.Code, rec.Body.String(), c.status)
			}
		})
	}

	pre := httptest.NewRequest(http.MethodOptions, "/api/v1/session/refresh", nil)
	pre.Header.Set("Origin", "https://pos.codevertexafrica.com")
	pre.Header.Set("Access-Control-Request-Method", http.MethodPost)
	pre.Header.Set("Access-Control-Request-Headers", "x-requested-with")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, pre)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Credentials") != "true" ||
		!strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "X-Requested-With") {
		t.Fatalf("preflight %d %v", rec.Code, rec.Header())
	}
}
