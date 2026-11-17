package handlers

import (
	"net"
	"net/http"
	"strings"

	httpware "github.com/Bengo-Hub/httpware"
)

// Headers a service sends with an S2S key validation so the IP allowlist is checked against the
// developer who called that service, not against the service's own pod address.
const (
	// HeaderInternalServiceKey carries the shared internal service key. X-API-Key cannot be
	// used for it because on the validate endpoint X-API-Key is the key being validated.
	HeaderInternalServiceKey = "X-Internal-Service-Key"
	// HeaderOriginalClientIP is the developer's IP as the calling service saw it.
	HeaderOriginalClientIP = "X-Original-Client-IP"
)

// SetInternalServiceKey lets the validate endpoint trust HeaderOriginalClientIP from callers
// that prove they are internal services. Empty disables forwarding (the direct IP is used).
func (h *APIKeyHandler) SetInternalServiceKey(key string) { h.internalKey = key }

// allowlistIP is the address an app's IP allowlist is checked against. A forwarded address is
// honoured only alongside a valid internal service key, so an outside caller cannot spoof it.
func (h *APIKeyHandler) allowlistIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if fwd := strings.TrimSpace(r.Header.Get(HeaderOriginalClientIP)); fwd != "" &&
		net.ParseIP(fwd) != nil &&
		httpware.ValidServiceKey(r, h.internalKey, HeaderInternalServiceKey) {
		return fwd
	}
	return getClientIP(r)
}
