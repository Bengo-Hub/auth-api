package auth

import (
	"testing"

	"github.com/bengobox/auth-api/internal/config"
)

// A sign-in on the accounts portal is the portal's own session: recorded with no client, so it
// does not count towards the app's session limit. Any other origin keeps the app's client.
func TestPortalSessionClient(t *testing.T) {
	s := &Service{cfg: &config.Config{App: config.AppConfig{AuthUIURL: "https://accounts.codevertexafrica.com"}}}
	for origin, want := range map[string]bool{
		"https://accounts.codevertexafrica.com":  true,
		"https://accounts.codevertexafrica.com/": true,
		"HTTPS://ACCOUNTS.CODEVERTEXAFRICA.COM":  true,
		"https://hadiafrica.com":                 false,
		"https://staging.hadiafrica.com":         false,
		"":                                       false,
	} {
		if got := s.isPortalOrigin(origin); got != want {
			t.Errorf("isPortalOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
	if got := (issueSessionInput{ClientID: "pos-ui", Portal: true}).sessionClientID(); got != "" {
		t.Errorf("a portal sign-in is recorded against %q, want no client", got)
	}
	if got := (issueSessionInput{ClientID: "hadia-ui"}).sessionClientID(); got != "hadia-ui" {
		t.Errorf("an app sign-in is recorded against %q, want hadia-ui", got)
	}
	if (&Service{cfg: &config.Config{}}).isPortalOrigin("") {
		t.Error("with no portal configured nothing is the portal")
	}
}
