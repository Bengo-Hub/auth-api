package handlers

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/pkg/imageutil"
)

// Tenant logos are stored inline as base64 data: URIs (see imageutil). Embedding them in session
// payloads made /auth/me and the login response megabytes large for users who belong to several
// tenants (a platform owner's /me was 1.5 MB, 2 to 15 s to download on every sign-in), since image
// data barely compresses. Session payloads now carry a short, versioned URL to the logo instead,
// served (and cached by browsers and Cloudflare) from GET /api/v1/tenants/{slug}/logo.

// logoPublicBase is the public origin of this API (the token issuer), set once at startup.
var logoPublicBase string

// SetLogoPublicBase sets the public origin used to build logo URLs, e.g. "https://sso.example.com".
func SetLogoPublicBase(base string) { logoPublicBase = strings.TrimRight(base, "/") }

// logoRef is the logo_url to put in a session payload: an inline data: URI becomes a versioned
// logo URL (the version changes whenever the logo does, so it can be cached for good); a hosted
// URL or an empty value is returned unchanged.
func logoRef(t *ent.Tenant) *string {
	if t == nil || t.LogoURL == nil || !strings.HasPrefix(*t.LogoURL, "data:") || logoPublicBase == "" {
		if t == nil {
			return nil
		}
		return t.LogoURL
	}
	u := logoPublicBase + "/api/v1/tenants/" + t.Slug + "/logo?v=" + logoVersion(t)
	return &u
}

// isOwnLogoRef reports whether a submitted logo_url is one of this API's own logo links (as
// handed out by logoRef), i.e. an unchanged logo echoed back by a form, not a new logo.
func isOwnLogoRef(u string) bool {
	return logoPublicBase != "" && strings.HasPrefix(u, logoPublicBase+"/api/v1/tenants/") && strings.Contains(u, "/logo")
}

// logoVersion identifies a tenant's current logo cheaply: the tenant's last update time plus the
// stored value's length. updated_at changes on every tenant update (logo included), so a new logo
// always gets a new version; hashing the stored image on every /me call cost CPU per member tenant.
func logoVersion(t *ent.Tenant) string {
	n := 0
	if t.LogoURL != nil {
		n = len(*t.LogoURL)
	}
	return strconv.FormatInt(t.UpdatedAt.UnixNano(), 36) + "-" + strconv.Itoa(n)
}

// GetTenantLogoPublic serves a tenant's logo image. Public, like the other tenant lookups (a logo
// is shown on sign-in pages). Inline logos are decoded and served with long-lived caching and an
// ETag; a hosted logo URL is redirected to.
// GET /api/v1/tenants/{slug}/logo
func (h *AdminHandler) GetTenantLogoPublic(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	t, err := h.ent.Tenant.Query().Where(tenant.SlugEQ(slug)).Only(r.Context())
	if err != nil {
		if ent.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not_found", "tenant not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "failed to get tenant", nil)
		return
	}
	if t.LogoURL == nil || *t.LogoURL == "" {
		writeError(w, http.StatusNotFound, "not_found", "tenant has no logo", nil)
		return
	}
	// Logos stored before the size limits are downscaled on the way out (memoised in imageutil).
	logo := imageutil.FitStoredLogo(*t.LogoURL)
	if !strings.HasPrefix(logo, "data:") {
		http.Redirect(w, r, logo, http.StatusFound)
		return
	}
	mime, data, ok := decodeDataURI(logo)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "tenant logo is not readable", nil)
		return
	}
	etag := `"` + logoVersion(t) + `"`
	w.Header().Set("ETag", etag)
	// A versioned request (?v=) never changes; an unversioned one is revalidated daily.
	if r.URL.Query().Get("v") != "" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if mime == "image/svg+xml" {
		// SVG can carry script; never let it run when opened directly.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// decodeDataURI splits "data:<mime>[;base64],<payload>" into its image type and bytes. Only image
// types are accepted.
func decodeDataURI(s string) (string, []byte, bool) {
	head, payload, found := strings.Cut(strings.TrimPrefix(s, "data:"), ",")
	if !found {
		return "", nil, false
	}
	parts := strings.Split(head, ";")
	mime := strings.ToLower(strings.TrimSpace(parts[0]))
	if !strings.HasPrefix(mime, "image/") {
		return "", nil, false
	}
	isB64 := false
	for _, p := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(p), "base64") {
			isB64 = true
		}
	}
	if !isB64 {
		return mime, []byte(payload), true
	}
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		if data, err = base64.RawStdEncoding.DecodeString(payload); err != nil {
			return "", nil, false
		}
	}
	return mime, data, true
}
