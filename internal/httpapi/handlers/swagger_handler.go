package handlers

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

//go:embed spec/openapi.json
var openapiSpec []byte

// externalDocTags are the only tags shown to a caller who isn't holding a genuine Codevertex
// platform App secret -- an anonymous visitor, or anyone with an invalid/non-platform secret.
// Everything else in the spec documents platform-admin-only operations (tenant/client/entitlement
// management, signing-key rotation) and has no reason to be served to that audience.
var externalDocTags = map[string]bool{
	"Auth":      true,
	"OAuth":     true,
	"Discovery": true,
	"Health":    true,
}

// SwaggerHandler serves the OpenAPI spec and its Swagger UI. The embedded spec is parsed once at
// startup; the external-only view is pre-computed at the same time so every request is a cheap
// map lookup, never a re-parse. Mirrors treasury-api's internal/http/handlers/swagger.go.
type SwaggerHandler struct {
	apiKeyHandler *APIKeyHandler
	fullSpec      map[string]any
	externalSpec  map[string]any
}

// NewSwaggerHandler builds the handler from the embedded openapi.json. apiKeyHandler may be nil
// (e.g. in a test binary that doesn't wire one) -- OpenAPIJSON simply always serves the
// external-only view in that case, never the internal one.
func NewSwaggerHandler(apiKeyHandler *APIKeyHandler) (*SwaggerHandler, error) {
	var full map[string]any
	if err := json.Unmarshal(openapiSpec, &full); err != nil {
		return nil, err
	}
	return &SwaggerHandler{
		apiKeyHandler: apiKeyHandler,
		fullSpec:      full,
		externalSpec:  filterSpecToTags(full, externalDocTags),
	}, nil
}

// isPrivilegedForInternalDocs reports whether a validated app secret belongs to a genuine
// platform-type App (roles=["superuser","service"], see ResolveAppToken) as opposed to a
// tenant-scoped App or a bare/invalid secret.
func isPrivilegedForInternalDocs(resp *ValidateAPIKeyResponse) bool {
	if resp == nil {
		return false
	}
	for _, role := range resp.Roles {
		if role == "superuser" {
			return true
		}
	}
	return false
}

func writeSwaggerCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
	w.Header().Set("Access-Control-Expose-Headers", "X-Docs-View, X-Docs-Environment")
	w.Header().Set("Access-Control-Max-Age", "3600")
}

// resolveAppSecretOptional validates the X-API-Key header (a pasted app secret or developer key)
// in-process via APIKeyHandler.ResolveAnyToken and returns the result, or nil if there's no header
// or it doesn't validate. Never rejects the request -- an invalid/missing secret here just means
// "anonymous," not "reject," since OpenAPIJSON always has a safe (external-only) response to fall
// back to. auth-api validates in-process (unlike treasury/notifications, which round-trip to
// auth-api over HTTP) since it IS auth-api -- calling itself over HTTP would be pointless.
func resolveAppSecretOptional(apiKeyHandler *APIKeyHandler, r *http.Request) *ValidateAPIKeyResponse {
	secret := r.Header.Get("X-API-Key")
	if apiKeyHandler == nil || secret == "" {
		return nil
	}
	resp, _, _, _, err := apiKeyHandler.ResolveAnyToken(r.Context(), r, secret)
	if err != nil {
		return nil
	}
	return resp
}

// OpenAPIJSON serves the OpenAPI/Swagger JSON specification: the full internal spec for a
// resolved platform App secret, the external-only subset for everyone else (anonymous visitors,
// tenant App/APIKey holders, and invalid secrets). Also reports the resolved view via the
// X-Docs-View response header, matching treasury-api's docs page contract.
func (h *SwaggerHandler) OpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		writeSwaggerCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeSwaggerCORSHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	resolved := resolveAppSecretOptional(h.apiKeyHandler, r)
	spec := h.externalSpec
	docsView := "external"
	environment := "none"
	if resolved != nil {
		environment = resolved.Environment
		if isPrivilegedForInternalDocs(resolved) {
			spec = h.fullSpec
			docsView = "internal"
		}
	}
	w.Header().Set("X-Docs-View", docsView)
	w.Header().Set("X-Docs-Environment", environment)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(spec)
}

// SwaggerUI serves the Swagger UI HTML page. See renderDocsHTML's doc comment for the app-secret
// unlock contract this page implements -- identical across treasury-api, auth-api, and
// notifications-api.
func (h *SwaggerHandler) SwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(renderDocsHTML("Auth Service API Docs"))
}

// renderDocsHTML builds the fleet-standard docs page: an app-secret ("bng_app_..." or a plain
// developer "bng_..." key) paste bar that drives two independent, server-verified unlocks --
// internal/full spec visibility (platform secrets only) and a sandbox/production badge (reflects
// the secret's real Environment) -- via the same X-API-Key header on both the spec fetch and every
// "Try it out" call. No credential ever unlocks anything client-side; OpenAPIJSON is the sole
// source of truth and reports its decision back via X-Docs-View/X-Docs-Environment headers.
func renderDocsHTML(title string) []byte {
	return []byte(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>` + title + `</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
      #docs-token-bar {
        display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
        padding: 10px 16px; background: #1b1b1b; color: #fff; font: 13px sans-serif;
      }
      #docs-token-bar input {
        flex: 1; min-width: 240px; max-width: 420px; padding: 6px 8px;
        border-radius: 4px; border: 1px solid #444; background: #111; color: #fff;
      }
      #docs-token-bar button {
        padding: 6px 14px; border-radius: 4px; border: none;
        background: #61affe; color: #0b1620; cursor: pointer; font-weight: 600;
      }
      #docs-token-bar span.hint { opacity: .75; }
      #docs-view-badge, #docs-env-badge {
        font-weight: 600; padding: 3px 10px; border-radius: 12px; font-size: 12px;
      }
      #docs-view-badge { background: #333; }
      #docs-env-badge.sandbox { background: #614a00; color: #ffd76b; }
      #docs-env-badge.production { background: #0b4a1f; color: #6bffa0; }
    </style>
  </head>
  <body>
    <div id="docs-token-bar">
      <span class="hint">Codevertex staff or developers with an app secret:</span>
      <input id="docs-token-input" type="password" placeholder="Paste your app secret (bng_app_... or bng_...)" />
      <button id="docs-token-apply">Unlock</button>
      <button id="docs-token-clear">Clear</button>
      <span id="docs-view-badge">External view</span>
      <span id="docs-env-badge" class="sandbox">Sandbox</span>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
    <script>
      const SECRET_KEY = 'codevertex_docs_app_secret';
      const specUrl = window.location.protocol + '//' + window.location.host + '/api/v1/openapi.json';

      function requestInterceptor(request) {
        // Carries the same pasted app secret onto every "Try it out" call as X-API-Key, so
        // testing a real request exercises the same sandbox/production credential distinction
        // enforced server-side -- unrelated to Swagger UI's own Authorize dialog, if the spec
        // also declares other security schemes.
        const secret = localStorage.getItem(SECRET_KEY);
        if (secret && request.headers && !request.headers['X-API-Key']) {
          request.headers['X-API-Key'] = secret;
        }
        return request;
      }

      function setBadges(docsView, environment) {
        const viewBadge = document.getElementById('docs-view-badge');
        viewBadge.textContent = docsView === 'internal' ? 'Internal view' : 'External view';
        const envBadge = document.getElementById('docs-env-badge');
        const env = environment === 'production' ? 'production' : 'sandbox';
        envBadge.textContent = env === 'production' ? 'Production' : 'Sandbox';
        envBadge.className = env;
      }

      function renderDocs(secret) {
        const headers = secret ? { 'X-API-Key': secret } : {};
        fetch(specUrl, { headers: headers })
          .then((res) => {
            setBadges(res.headers.get('X-Docs-View'), res.headers.get('X-Docs-Environment'));
            return res.json();
          })
          .then((spec) => {
            window.ui = SwaggerUIBundle({
              spec: spec,
              dom_id: '#swagger-ui',
              presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
              layout: 'BaseLayout',
              deepLinking: true,
              filter: true,
              persistAuthorization: true,
              requestInterceptor: requestInterceptor,
            });
          });
      }

      window.onload = () => {
        const saved = localStorage.getItem(SECRET_KEY) || '';
        document.getElementById('docs-token-input').value = saved;
        renderDocs(saved);

        document.getElementById('docs-token-apply').addEventListener('click', () => {
          const secret = document.getElementById('docs-token-input').value.trim();
          localStorage.setItem(SECRET_KEY, secret);
          renderDocs(secret);
        });
        document.getElementById('docs-token-clear').addEventListener('click', () => {
          localStorage.removeItem(SECRET_KEY);
          document.getElementById('docs-token-input').value = '';
          renderDocs('');
        });
      }
    </script>
  </body>
</html>`)
}
