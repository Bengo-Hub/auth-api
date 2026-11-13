package handlers

import (
	"reflect"
	"testing"
)

func TestNormalizeTenantSupport(t *testing.T) {
	cases := []struct {
		name    string
		in      any
		want    map[string]any
		wantErr bool
	}{
		{
			name: "all fields, phones normalised to E.164",
			in:   map[string]any{"email": " Help@Shop.co.ke ", "phone": "0712 345 678", "whatsapp": "254712345678"},
			want: map[string]any{"email": "help@shop.co.ke", "phone": "+254712345678", "whatsapp": "+254712345678"},
		},
		{
			name: "international number with spaces",
			in:   map[string]any{"phone": "+254 743 793 901"},
			want: map[string]any{"phone": "+254743793901"},
		},
		{
			name: "email only",
			in:   map[string]any{"email": "support@codevertexafrica.com", "phone": "", "whatsapp": nil},
			want: map[string]any{"email": "support@codevertexafrica.com"},
		},
		{name: "null clears", in: nil, want: nil},
		{name: "every field blank clears", in: map[string]any{"email": "", "phone": " "}, want: nil},
		{name: "not an object", in: "help@shop.co.ke", wantErr: true},
		{name: "unknown field", in: map[string]any{"email": "help@shop.co.ke", "fax": "1"}, wantErr: true},
		{name: "email with a display name", in: map[string]any{"email": "Help <help@shop.co.ke>"}, wantErr: true},
		{name: "email without a domain dot", in: map[string]any{"email": "help@shop"}, wantErr: true},
		{name: "not an email", in: map[string]any{"email": "help"}, wantErr: true},
		{name: "email not text", in: map[string]any{"email": 12}, wantErr: true},
		{name: "invalid phone", in: map[string]any{"phone": "12345"}, wantErr: true},
		{name: "invalid whatsapp", in: map[string]any{"whatsapp": "call me"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeTenantSupport(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyTenantSupportMetadata(t *testing.T) {
	meta := map[string]any{"contact_email": "info@shop.co.ke"}
	if err := applyTenantSupportMetadata(meta, map[string]any{"email": "help@shop.co.ke"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := meta[MetadataKeySupport].(map[string]any); s["email"] != "help@shop.co.ke" {
		t.Fatalf("support not stored: %v", meta)
	}
	if err := applyTenantSupportMetadata(meta, map[string]any{"email": "nope"}); err == nil {
		t.Fatal("an invalid email must be refused")
	}
	if s, _ := meta[MetadataKeySupport].(map[string]any); s["email"] != "help@shop.co.ke" {
		t.Fatalf("a refused value must leave the stored one: %v", meta)
	}
	if err := applyTenantSupportMetadata(meta, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := meta[MetadataKeySupport]; ok {
		t.Fatalf("null must remove the support contact: %v", meta)
	}
	if meta["contact_email"] != "info@shop.co.ke" {
		t.Fatal("other metadata must be kept")
	}
}

func TestTenantSupportPayload(t *testing.T) {
	got := tenantSupportPayload(map[string]any{"support": map[string]any{"email": "help@shop.co.ke", "phone": "+254712345678"}})
	want := map[string]any{"email": "help@shop.co.ke", "phone": "+254712345678", "whatsapp": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	empty := map[string]any{"email": "", "phone": "", "whatsapp": ""}
	if got := tenantSupportPayload(nil); !reflect.DeepEqual(got, empty) {
		t.Fatalf("nil metadata: %v", got)
	}
	if got := tenantSupportPayload(map[string]any{"support": "x"}); !reflect.DeepEqual(got, empty) {
		t.Fatalf("malformed: %v", got)
	}
}

// The support contact is not hidden from the public tenant lookups: it is how customers reach the
// tenant, and the shared tenant cache reads it from there.
func TestSupportIsPublicMetadata(t *testing.T) {
	out := publicMetadata(map[string]any{"support": map[string]any{"email": "help@shop.co.ke"}})
	if _, ok := out["support"]; !ok {
		t.Fatal("support must stay in the public metadata")
	}
}
