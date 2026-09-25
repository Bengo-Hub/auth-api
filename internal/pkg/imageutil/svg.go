package imageutil

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// MaxSVGBytes bounds an inline SVG logo. Vector logos are small; anything
// larger is almost always an embedded raster or an editor dump.
const MaxSVGBytes = 100 * 1024

var (
	svgRootPattern     = regexp.MustCompile(`(?is)<svg[\s>]`)
	svgEventAttr       = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	svgExternalHref    = regexp.MustCompile(`(?i)(?:xlink:)?href\s*=\s*["']\s*(?:https?:|//|javascript:|data:(?:text|application))`)
	svgForbiddenMarkup = []string{"<script", "<foreignobject", "<iframe", "<embed", "<object", "javascript:", "<!entity", "<!doctype"}
)

// isSVGDataURI reports whether raw is an SVG data URI (base64 or URL-encoded).
func isSVGDataURI(raw string) bool {
	return strings.HasPrefix(strings.ToLower(raw), "data:image/svg+xml")
}

// ValidateSVGDataURI checks an SVG logo submitted as a data URI and returns it
// re-encoded as base64. Browsers never run scripts inside an SVG loaded through
// <img>, but the logo is also served to PWA manifests, emails and pages that
// may inline it, so active content and external references are rejected
// outright rather than stripped.
func ValidateSVGDataURI(raw string) (string, error) {
	comma := strings.IndexByte(raw, ',')
	if comma < 0 {
		return "", fmt.Errorf("malformed data URI")
	}
	meta, payload := raw[:comma], raw[comma+1:]

	var body []byte
	if strings.Contains(meta, ";base64") {
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", fmt.Errorf("invalid base64 SVG data: %w", err)
		}
		body = decoded
	} else {
		decoded, err := url.PathUnescape(payload)
		if err != nil {
			return "", fmt.Errorf("invalid URL-encoded SVG data: %w", err)
		}
		body = []byte(decoded)
	}

	if err := ValidateSVG(body); err != nil {
		return "", err
	}
	return toDataURL("image/svg+xml", body), nil
}

// ValidateSVG rejects SVG markup that is too large, is not an SVG document, or
// carries scripts, event handlers, embedded HTML or external references.
func ValidateSVG(body []byte) error {
	if len(body) == 0 {
		return fmt.Errorf("empty SVG")
	}
	if len(body) > MaxSVGBytes {
		return fmt.Errorf("SVG too large (%dKB), keep vector logos under %dKB", len(body)/1024, MaxSVGBytes/1024)
	}
	text := string(body)
	if !svgRootPattern.MatchString(text) {
		return fmt.Errorf("file is not an SVG image")
	}
	lower := strings.ToLower(text)
	for _, bad := range svgForbiddenMarkup {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("SVG contains unsupported content (%s)", strings.TrimPrefix(bad, "<"))
		}
	}
	if svgEventAttr.MatchString(text) {
		return fmt.Errorf("SVG contains event handler attributes")
	}
	if svgExternalHref.MatchString(text) {
		return fmt.Errorf("SVG references external resources")
	}
	return nil
}
