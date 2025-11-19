package handlers

import (
	_ "embed"
	"net/http"
)

//go:embed spec/openapi.json
var openapiSpec []byte

func OpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openapiSpec)
}

func SwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Auth Service API Docs</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
    <script>
      window.onload = () => {
        // Use the same protocol as the current page to avoid HTTP/HTTPS mismatch
        const specUrl = window.location.protocol + '//' + window.location.host + '/api/v1/openapi.json';
        window.ui = SwaggerUIBundle({
          url: specUrl,
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
          layout: "BaseLayout",
          deepLinking: true,
          filter: true,
          persistAuthorization: true,
          requestInterceptor: (request) => {
            // Automatically add "Bearer " prefix to Authorization header if missing
            if (request.headers && request.headers.Authorization) {
              const authHeader = request.headers.Authorization;
              // Check if it doesn't already start with "Bearer " (case-insensitive)
              if (!/^bearer\s+/i.test(authHeader)) {
                request.headers.Authorization = 'Bearer ' + authHeader.trim();
              }
            }
            return request;
          }
        })
      }
    </script>
  </body>
</html>`))
}
