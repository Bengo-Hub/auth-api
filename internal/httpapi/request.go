package httpapi

import (
	"encoding/json"
	"net/http"

	ratelimit "github.com/Bengo-Hub/shared-ratelimit"
)

// DecodeJSON reads the request body into v.
func DecodeJSON(r *http.Request, v any) error {
	defer r.Body.Close() //nolint:errcheck
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// ClientIP is the caller's address as the ingress established it, never a client-sent forwarding
// header (shared-ratelimit ClientIP).
func ClientIP(r *http.Request) string {
	return ratelimit.ClientIP(r)
}

// UserAgent returns the request user agent string.
func UserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}
