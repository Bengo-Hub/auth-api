package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
)

func TestLogoRef(t *testing.T) {
	SetLogoPublicBase("https://sso.example.com/")
	t.Cleanup(func() { SetLogoPublicBase("") })

	inline := "data:image/png;base64," + strings.Repeat("A", 4000)
	got := logoRef(&ent.Tenant{Slug: "small-steps", LogoURL: &inline})
	if got == nil || !strings.HasPrefix(*got, "https://sso.example.com/api/v1/tenants/small-steps/logo?v=") || len(*got) > 120 {
		t.Fatalf("inline logo ref = %v", got)
	}
	// Same logo, same version; a changed logo gets a new version.
	other := inline + "B"
	if again := logoRef(&ent.Tenant{Slug: "small-steps", LogoURL: &inline}); *again != *got {
		t.Fatal("version not stable")
	}
	if changed := logoRef(&ent.Tenant{Slug: "small-steps", LogoURL: &other}); *changed == *got {
		t.Fatal("version did not change with the logo")
	}
	hosted := "https://cdn.example.com/logo.png"
	if r := logoRef(&ent.Tenant{Slug: "x", LogoURL: &hosted}); r == nil || *r != hosted {
		t.Fatalf("hosted logo changed: %v", r)
	}
	if !isOwnLogoRef(*got) || isOwnLogoRef(hosted) || isOwnLogoRef(inline) {
		t.Fatal("isOwnLogoRef misclassifies")
	}
	if r := logoRef(&ent.Tenant{Slug: "x"}); r != nil {
		t.Fatalf("empty logo = %v", r)
	}
}

func TestDecodeDataURI(t *testing.T) {
	mime, data, ok := decodeDataURI("data:image/png;base64,iVBORw0KGgo=")
	if !ok || mime != "image/png" || !bytes.HasPrefix(data, []byte("\x89PNG")) {
		t.Fatalf("png = %q %v %v", mime, data, ok)
	}
	if mime, data, ok := decodeDataURI("data:image/svg+xml,<svg/>"); !ok || mime != "image/svg+xml" || string(data) != "<svg/>" {
		t.Fatalf("svg = %q %q %v", mime, data, ok)
	}
	if _, _, ok := decodeDataURI("data:text/html;base64,PHNjcmlwdD4="); ok {
		t.Fatal("non-image data URI accepted")
	}
	if _, _, ok := decodeDataURI("data:image/png;base64"); ok {
		t.Fatal("malformed data URI accepted")
	}
}
