package microsoft

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func idToken(t *testing.T, claims jwt.MapClaims) *oauth2.Token {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("unit-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return (&oauth2.Token{AccessToken: "a"}).WithExtra(map[string]any{"id_token": raw})
}

func TestVerifiedEmail(t *testing.T) {
	cases := []struct {
		name   string
		token  *oauth2.Token
		want   string
		wantOK bool
	}{
		{"no token", nil, "", false},
		{"no id token", &oauth2.Token{AccessToken: "a"}, "", false},
		{"email without xms_edov", idToken(t, jwt.MapClaims{"email": "a@x.org"}), "", false},
		{"xms_edov false", idToken(t, jwt.MapClaims{"email": "a@x.org", "xms_edov": false}), "", false},
		{"xms_edov true", idToken(t, jwt.MapClaims{"email": "a@x.org", "xms_edov": true}), "a@x.org", true},
		{"xms_edov string 1", idToken(t, jwt.MapClaims{"email": "a@x.org", "xms_edov": "1"}), "a@x.org", true},
		{"xms_edov without email", idToken(t, jwt.MapClaims{"xms_edov": true}), "", false},
		{"garbage", (&oauth2.Token{}).WithExtra(map[string]any{"id_token": "not.a.jwt"}), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := VerifiedEmail(c.token)
			if got != c.want || ok != c.wantOK {
				t.Fatalf("VerifiedEmail = %q, %v; want %q, %v", got, ok, c.want, c.wantOK)
			}
		})
	}
}
