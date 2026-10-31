package httpapi

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bengobox/auth-api/internal/httpapi/handlers"
)

// TestOpenAPIPathsExist keeps the published spec honest: every path and method it documents must
// be a real route. The spec is hand-written (handlers/spec/openapi.json), so without this a renamed
// or removed route would keep being advertised to integrators.
func TestOpenAPIPathsExist(t *testing.T) {
	swagger, err := handlers.NewSwaggerHandler(nil)
	if err != nil {
		t.Fatal(err)
	}
	pass := func(next http.Handler) http.Handler { return next }
	r := NewRouter(RouterDeps{
		HealthHandler:      func(http.ResponseWriter, *http.Request) {},
		DomainHandler:      &handlers.DomainHandler{},
		SwaggerHandler:     swagger,
		RequireAuthHandler: pass,
		TryAuthHandler:     pass,
		RateLimitLogin:     pass,
		RateLimitToken:     pass,
		RateLimitSensitive: pass,
		EquityPortalAuth:   pass,
	})

	routes := map[string]bool{}
	err = chi.Walk(r.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes[method+" "+strings.TrimSuffix(route, "/")] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile("handlers/spec/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for path, ops := range spec.Paths {
		for method := range ops {
			m := strings.ToUpper(method)
			switch m {
			case "GET", "POST", "PUT", "PATCH", "DELETE":
			default:
				continue // parameters, summary and other non-operation keys
			}
			if !routes[m+" "+path] {
				t.Errorf("spec documents %s %s but the router has no such route", m, path)
			}
		}
	}
}
