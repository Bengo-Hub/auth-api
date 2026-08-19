package handlers

import "testing"

func TestValidateAndNormalizePhone(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"valid Kenyan E.164", "+254743793901", "+254743793901", false},
		{"valid with spaces", "+254 743 793 901", "+254743793901", false},
		{"missing country code", "0743793901", "", true},
		{"garbage", "not-a-phone", "", true},
		{"empty", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := validateAndNormalizePhone(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got none (normalized: %q)", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestIsValidCountryCode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"KE", true},
		{"ke", true}, // case-insensitive
		{"US", true},
		{"Kenya", false},
		{"ZZ", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isValidCountryCode(c.in); got != c.want {
			t.Errorf("isValidCountryCode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
