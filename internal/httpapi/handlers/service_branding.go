package handlers

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bengobox/auth-api/internal/pkg/imageutil"
)

// MetadataKeyServiceBranding is the tenant metadata key holding per-service app
// names and icons, e.g. urban-loft naming its ordering app "Urban Eats":
//
//	"service_branding": {
//	  "ordering": {"name": "Urban Eats", "short_name": "Urban Eats", "icon_url": "data:image/svg+xml;base64,..."},
//	  "rider":    {"name": "Urban Loft Riders"}
//	}
//
// Frontends read it from GET /api/v1/tenants/by-slug/{slug} (metadata) and fall
// back to their platform default name/icon when a service has no entry.
const MetadataKeyServiceBranding = "service_branding"

const (
	maxServiceBrandingEntries = 20
	maxServiceNameLen         = 60
	maxServiceShortNameLen    = 24
	maxServiceTaglineLen      = 120
)

var (
	serviceKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)
	hexColorPattern   = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
)

// mergeServiceBranding validates the service_branding value submitted in a
// tenant update and merges it into the existing one. Each service entry is
// replaced as a whole; an entry sent as null or with every field blank removes
// that service's override so it falls back to the platform default.
func mergeServiceBranding(existing any, submitted any) (map[string]any, error) {
	incoming, ok := submitted.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("service_branding must be an object keyed by service")
	}

	merged := map[string]any{}
	if current, ok := existing.(map[string]any); ok {
		for k, v := range current {
			merged[k] = v
		}
	}

	for service, raw := range incoming {
		key := strings.ToLower(strings.TrimSpace(service))
		if !serviceKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("service_branding: invalid service key %q", service)
		}
		if raw == nil {
			delete(merged, key)
			continue
		}
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("service_branding.%s must be an object", key)
		}
		clean, err := normalizeServiceBrandingEntry(key, entry)
		if err != nil {
			return nil, err
		}
		if len(clean) == 0 {
			delete(merged, key)
			continue
		}
		merged[key] = clean
	}

	if len(merged) > maxServiceBrandingEntries {
		return nil, fmt.Errorf("service_branding: at most %d services can be branded", maxServiceBrandingEntries)
	}
	return merged, nil
}

func normalizeServiceBrandingEntry(service string, entry map[string]any) (map[string]any, error) {
	clean := map[string]any{}

	text := func(field string, limit int) (string, error) {
		raw, present := entry[field]
		if !present || raw == nil {
			return "", nil
		}
		s, ok := raw.(string)
		if !ok {
			return "", fmt.Errorf("service_branding.%s.%s must be text", service, field)
		}
		s = strings.Join(strings.Fields(s), " ")
		if len([]rune(s)) > limit {
			return "", fmt.Errorf("service_branding.%s.%s is too long (max %d characters)", service, field, limit)
		}
		return s, nil
	}

	name, err := text("name", maxServiceNameLen)
	if err != nil {
		return nil, err
	}
	shortName, err := text("short_name", maxServiceShortNameLen)
	if err != nil {
		return nil, err
	}
	tagline, err := text("tagline", maxServiceTaglineLen)
	if err != nil {
		return nil, err
	}
	themeColor, err := text("theme_color", 7)
	if err != nil {
		return nil, err
	}
	// icon_url is not whitespace-folded: data URIs are validated byte for byte.
	iconURL := ""
	if raw, present := entry["icon_url"]; present && raw != nil {
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("service_branding.%s.icon_url must be text", service)
		}
		iconURL = strings.TrimSpace(s)
	}

	if name != "" {
		clean["name"] = name
	}
	if shortName != "" {
		clean["short_name"] = shortName
	} else if name != "" && len([]rune(name)) <= 12 {
		// PWA launchers truncate long labels; only derive short_name from a
		// name that already fits.
		clean["short_name"] = name
	}
	if tagline != "" {
		clean["tagline"] = tagline
	}
	if themeColor != "" {
		if !hexColorPattern.MatchString(themeColor) {
			return nil, fmt.Errorf("service_branding.%s.theme_color must be a hex colour like #0F766E", service)
		}
		clean["theme_color"] = themeColor
	}
	if iconURL != "" {
		if !strings.HasPrefix(iconURL, "data:") && !strings.HasPrefix(iconURL, "https://") {
			return nil, fmt.Errorf("service_branding.%s.icon_url must be an https URL or an uploaded image", service)
		}
		normalized, err := imageutil.ValidateAndCompressLogoURL(iconURL)
		if err != nil {
			return nil, fmt.Errorf("service_branding.%s.icon_url: %w", service, err)
		}
		clean["icon_url"] = normalized
	}
	return clean, nil
}
