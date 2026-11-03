package handlers

import (
	"strings"
	"testing"
)

func TestPublicOTPEmail(t *testing.T) {
	cases := map[string]string{
		" Visitor@Example.com ":   "visitor@example.com",
		"not-an-email":            "",
		"Eve <eve@example.com>":   "",
		"a@b.co, other@evil.test": "",
		"":                        "",
	}
	for in, want := range cases {
		if got := publicOTPEmail(in); got != want {
			t.Errorf("publicOTPEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateIntegrationRequestBody(t *testing.T) {
	valid := func() createIntegrationRequestBody {
		return createIntegrationRequestBody{
			RequestType:     "camera_systems",
			IntegrationMode: "self_serve",
			RequesterName:   "Sharley Mwajuma",
			RequesterEmail:  "sharley@example.com",
			Notes:           "Hello World!",
		}
	}
	cases := []struct {
		name   string
		mutate func(*createIntegrationRequestBody)
		want   string
	}{
		{"widget form body", func(*createIntegrationRequestBody) {}, ""},
		{"trims before checking", func(b *createIntegrationRequestBody) { b.RequesterEmail = "  sharley@example.com " }, ""},
		{"missing name", func(b *createIntegrationRequestBody) { b.RequesterName = "  " }, "requester_name and requester_email are required"},
		{"bad email", func(b *createIntegrationRequestBody) { b.RequesterEmail = "not-an-email" }, "requester_email is not a valid email address"},
		{"display-name email", func(b *createIntegrationRequestBody) { b.RequesterEmail = "Eve <eve@example.com>" }, "requester_email is not a valid email address"},
		{"notes too long", func(b *createIntegrationRequestBody) { b.Notes = strings.Repeat("a", 2001) }, "notes is too long"},
		{"request_type charset", func(b *createIntegrationRequestBody) { b.RequestType = "camera systems<script>" }, "request_type may only contain lowercase letters, digits and underscores"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := valid()
			tc.mutate(&b)
			if got := validateIntegrationRequestBody(&b); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
