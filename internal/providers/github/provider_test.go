package github

import "testing"

func TestPrimaryVerifiedEmail(t *testing.T) {
	cases := []struct {
		name   string
		emails []EmailRecord
		want   string
	}{
		{"none", nil, ""},
		{"primary verified", []EmailRecord{{Email: "b@x.org", Verified: true}, {Email: "a@x.org", Primary: true, Verified: true}}, "a@x.org"},
		{"primary unverified", []EmailRecord{{Email: "a@x.org", Primary: true}, {Email: "b@x.org", Verified: true}}, ""},
		{"verified but not primary", []EmailRecord{{Email: "b@x.org", Verified: true}}, ""},
	}
	for _, c := range cases {
		if got := PrimaryVerifiedEmail(c.emails); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
