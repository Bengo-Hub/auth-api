package handlers

import (
	"fmt"
	"net/mail"
	"strings"
)

// MetadataKeySupport is the tenant metadata key holding the tenant's support contact (support
// routing, 12 November 2026):
//
//	"support": {"email": "help@shop.co.ke", "phone": "+254712345678", "whatsapp": "+254712345678"}
//
// A tenant's tickets and support mail go out through these; services read them through the shared
// tenant cache (cache.ResolveSupportContact), which falls back to contact_email and contact_phone
// when a field is empty. The codevertex platform tenant's support email is
// support@codevertexafrica.com (seeded). Edited with the rest of the profile through
// PUT /api/v1/tenants/{tenant_id}, so the same tenant admins who edit contact_email edit it.
const MetadataKeySupport = "support"

// maxSupportEmailLen bounds the support email (RFC 5321 path limit).
const maxSupportEmailLen = 254

// normalizeTenantSupport validates the support value submitted in a tenant update and returns the
// clean object to store. The object is replaced as a whole: a field left out or blank is cleared.
// null, or an object with every field blank, returns nil (the caller removes the key, and every
// service falls back to the contact email and phone). The email must be a bare address; phone and
// whatsapp are normalised to E.164 ("0712...", "254712..." and "+254 712 ..." all become
// "+254712..."), the same rule as the S2S phone lookup.
func normalizeTenantSupport(submitted any) (map[string]any, error) {
	if submitted == nil {
		return nil, nil
	}
	in, ok := submitted.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("support must be an object with email, phone and whatsapp")
	}
	for k := range in {
		switch k {
		case "email", "phone", "whatsapp":
		default:
			return nil, fmt.Errorf("support.%s is not a support field (use email, phone or whatsapp)", k)
		}
	}
	text := func(field string) (string, error) {
		raw, present := in[field]
		if !present || raw == nil {
			return "", nil
		}
		s, ok := raw.(string)
		if !ok {
			return "", fmt.Errorf("support.%s must be text", field)
		}
		return strings.TrimSpace(s), nil
	}

	clean := map[string]any{}
	email, err := text("email")
	if err != nil {
		return nil, err
	}
	if email != "" {
		email = strings.ToLower(email)
		addr, err := mail.ParseAddress(email)
		if err != nil || addr.Address != email || len(email) > maxSupportEmailLen || !strings.Contains(email[strings.LastIndex(email, "@")+1:], ".") {
			return nil, fmt.Errorf("support.email is not a valid email address")
		}
		clean["email"] = email
	}
	for _, field := range []string{"phone", "whatsapp"} {
		raw, err := text(field)
		if err != nil {
			return nil, err
		}
		if raw == "" {
			continue
		}
		p, err := normalizeLookupPhone(raw)
		if err != nil {
			return nil, fmt.Errorf("support.%s is not a valid phone number (use the international form, e.g. +254712345678)", field)
		}
		clean[field] = p
	}
	if len(clean) == 0 {
		return nil, nil
	}
	return clean, nil
}

// tenantSupportPayload is the support contact as published on auth.tenant.created/updated and as
// returned to readers: always the three keys, empty when unset, so a consumer can tell "cleared"
// from "not sent". A malformed stored value reads as empty.
func tenantSupportPayload(meta map[string]any) map[string]any {
	out := map[string]any{"email": "", "phone": "", "whatsapp": ""}
	stored, ok := meta[MetadataKeySupport].(map[string]any)
	if !ok {
		return out
	}
	for k := range out {
		if s, ok := stored[k].(string); ok {
			out[k] = s
		}
	}
	return out
}

// applyTenantSupportMetadata validates a submitted support value into metadata (the tenant update
// merge): a valid value is stored, an empty one removes the key. The error is the 400 message.
func applyTenantSupportMetadata(metadata map[string]any, submitted any) error {
	clean, err := normalizeTenantSupport(submitted)
	if err != nil {
		return err
	}
	if clean == nil {
		delete(metadata, MetadataKeySupport)
		return nil
	}
	metadata[MetadataKeySupport] = clean
	return nil
}
