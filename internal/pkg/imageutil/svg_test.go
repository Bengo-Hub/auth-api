package imageutil

import (
	"encoding/base64"
	"strings"
	"testing"
)

const sampleSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#0F766E"/></svg>`

func TestValidateAndCompressLogoURL_SVGBase64(t *testing.T) {
	in := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(sampleSVG))
	out, err := ValidateAndCompressLogoURL(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != in {
		t.Fatalf("SVG should be kept as-is, got %q", out)
	}
}

func TestValidateAndCompressLogoURL_SVGURLEncoded(t *testing.T) {
	in := "data:image/svg+xml;utf8," + strings.ReplaceAll(sampleSVG, "#", "%23")
	out, err := ValidateAndCompressLogoURL(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "data:image/svg+xml;base64,") {
		t.Fatalf("URL-encoded SVG should be re-encoded as base64, got %q", out)
	}
}

func TestValidateSVG_RejectsActiveContent(t *testing.T) {
	cases := map[string]string{
		"script":   `<svg><script>alert(1)</script></svg>`,
		"onload":   `<svg onload="alert(1)"></svg>`,
		"foreign":  `<svg><foreignObject><div/></foreignObject></svg>`,
		"external": `<svg><image href="https://example.com/x.png"/></svg>`,
		"js href":  `<svg><a xlink:href="javascript:alert(1)"/></svg>`,
		"entity":   `<!DOCTYPE svg [<!ENTITY x "y">]><svg></svg>`,
		"not svg":  `<html><body/></html>`,
	}
	for name, body := range cases {
		if err := ValidateSVG([]byte(body)); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestValidateSVG_AllowsInternalReferences(t *testing.T) {
	body := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><defs><linearGradient id="g"/></defs><use href="#g"/><rect fill="url(#g)"/></svg>`
	if err := ValidateSVG([]byte(body)); err != nil {
		t.Fatalf("internal references must be allowed: %v", err)
	}
}
