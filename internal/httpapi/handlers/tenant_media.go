package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/Bengo-Hub/httpware/objectstore"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/predicate"
	"github.com/bengobox/auth-api/internal/ent/tenant"
)

// Tenant branding images (the organisation logo and the per-service icons in
// metadata.service_branding) live on the shared object storage (httpware/objectstore, public
// bucket) under auth/<tenant_id>/logos/<group>/<content hash>.<ext>. The tenant row keeps the public
// link, because every service reads logo_url as a URL (tenant cache, events, document PDFs).
// Uploads still arrive as data: URIs from auth-ui and are validated and compressed by imageutil
// first. Without object storage configured (local development) they stay inline as before.

// logoStore is the shared object storage, set once at startup.
var logoStore *objectstore.Store

// SetLogoStore wires the shared object storage for tenant branding images.
func SetLogoStore(s *objectstore.Store) { logoStore = s }

const (
	logoGroupBrand        = "brand"
	logoGroupServiceIcons = "service-icons"
)

// persistImageRef stores an inline data: image (already validated by imageutil) and returns its
// public link; any other value (a hosted URL, an empty value) is returned unchanged, as is the data
// URI when no object storage is configured. The name is a content hash, so saving the same image
// again reuses the stored file.
func persistImageRef(ctx context.Context, tenantID uuid.UUID, raw, group string) (string, error) {
	if !strings.HasPrefix(raw, "data:") || !logoStore.Remote() {
		return raw, nil
	}
	comma := strings.IndexByte(raw, ',')
	if comma < 0 || !strings.Contains(raw[:comma], ";base64") {
		return "", fmt.Errorf("malformed image data")
	}
	mime := strings.TrimSuffix(strings.TrimPrefix(raw[:comma], "data:"), ";base64")
	data, err := base64.StdEncoding.DecodeString(raw[comma+1:])
	if err != nil {
		return "", fmt.Errorf("invalid image data: %w", err)
	}
	// Trust the bytes, not the label: browsers often label a JPEG as image/png. SVG is text and
	// sniffs as text/xml, so its declared type is kept.
	if mime != "image/svg+xml" {
		if sniffed := http.DetectContentType(data); strings.HasPrefix(sniffed, "image/") {
			mime = sniffed
		}
	}
	ext := map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/svg+xml": ".svg", "image/webp": ".webp", "image/gif": ".gif"}[mime]
	if ext == "" {
		return "", fmt.Errorf("unsupported image type %q", mime)
	}
	sum := sha256.Sum256(data)
	key, err := logoStore.Key(objectstore.Owner{TenantID: tenantID.String()}, objectstore.TypeLogos, group, hex.EncodeToString(sum[:16])+ext)
	if err != nil {
		return "", err
	}
	exists, err := logoStore.Exists(ctx, key)
	if err != nil {
		return "", fmt.Errorf("check stored image: %w", err)
	}
	if !exists {
		if err := logoStore.Put(ctx, key, data, mime); err != nil {
			return "", fmt.Errorf("store image: %w", err)
		}
	}
	return logoStore.URL(key), nil
}

// persistBrandingIcons stores the inline service icons of a service_branding map in place.
func persistBrandingIcons(ctx context.Context, tenantID uuid.UUID, branding map[string]any) error {
	for _, v := range branding {
		entry, ok := v.(map[string]any)
		if !ok {
			continue
		}
		icon, _ := entry["icon_url"].(string)
		if !strings.HasPrefix(icon, "data:") {
			continue
		}
		link, err := persistImageRef(ctx, tenantID, icon, logoGroupServiceIcons)
		if err != nil {
			return err
		}
		entry["icon_url"] = link
	}
	return nil
}

// brandingIcons lists the icon links of a service_branding value.
func brandingIcons(v any) []string {
	m, _ := v.(map[string]any)
	var out []string
	for _, e := range m {
		if entry, ok := e.(map[string]any); ok {
			if icon, _ := entry["icon_url"].(string); icon != "" {
				out = append(out, icon)
			}
		}
	}
	return out
}

// releaseTenantImages deletes stored branding images a tenant stopped using (a replaced logo or
// service icon), keeping storage to the images in use. Only this service's own files are deleted,
// and only when no other tenant row still links to them. Best effort, after the save.
func (h *AdminHandler) releaseTenantImages(ctx context.Context, before, after []string) {
	keep := map[string]bool{}
	for _, u := range after {
		keep[u] = true
	}
	for _, old := range before {
		if old == "" || keep[old] || !logoStore.Owned(old) {
			continue
		}
		keep[old] = true // never twice
		used, err := h.ent.Tenant.Query().Where(tenant.LogoURL(old)).Exist(ctx)
		if err != nil || used {
			continue
		}
		if err := logoStore.Delete(ctx, old); err != nil {
			h.logger.Warn("replaced branding image not deleted from storage", zap.String("url", old), zap.Error(err))
		}
	}
}

// tenantImages lists a tenant's stored branding image links (logo and service icons).
func tenantImages(t *ent.Tenant) []string {
	if t == nil {
		return nil
	}
	var out []string
	if t.LogoURL != nil && *t.LogoURL != "" {
		out = append(out, *t.LogoURL)
	}
	if t.Metadata != nil {
		out = append(out, brandingIcons(t.Metadata[MetadataKeyServiceBranding])...)
	}
	return out
}

// RelinkInlineImages moves every tenant logo and service icon still stored inline as a data: URI
// to object storage, updates the row, drops the shared tenant cache entry and publishes
// auth.tenant.updated so services refresh what they hold. It only touches rows that still carry
// inline images, so after the first run it finds nothing; it is safe on several replicas at once
// (content hash names, same values written). Run in the background at startup.
func (h *AdminHandler) RelinkInlineImages(ctx context.Context) (int, error) {
	if !logoStore.Remote() {
		return 0, nil
	}
	// metadata is jsonb; its text form writes `"icon_url": "data:...` for an inline icon.
	inlineIcon := predicate.Tenant(func(s *sql.Selector) {
		s.Where(sql.P(func(b *sql.Builder) {
			b.WriteString(s.C(tenant.FieldMetadata)).WriteString("::text LIKE ").Arg(`%"icon_url": "data:%`)
		}))
	})
	rows, err := h.ent.Tenant.Query().
		Where(tenant.Or(tenant.LogoURLHasPrefix("data:"), inlineIcon)).
		All(ctx)
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, t := range rows {
		update := h.ent.Tenant.UpdateOneID(t.ID)
		changed := false
		if t.LogoURL != nil && strings.HasPrefix(*t.LogoURL, "data:") {
			link, err := persistImageRef(ctx, t.ID, *t.LogoURL, logoGroupBrand)
			if err != nil {
				h.logger.Warn("inline logo not moved", zap.String("tenant", t.Slug), zap.Error(err))
			} else {
				update.SetLogoURL(link)
				changed = true
			}
		}
		if t.Metadata != nil {
			if branding, ok := t.Metadata[MetadataKeyServiceBranding].(map[string]any); ok {
				if err := persistBrandingIcons(ctx, t.ID, branding); err != nil {
					h.logger.Warn("inline service icons not moved", zap.String("tenant", t.Slug), zap.Error(err))
				} else {
					meta := map[string]any{}
					for k, v := range t.Metadata {
						meta[k] = v
					}
					meta[MetadataKeyServiceBranding] = branding
					update.SetMetadata(meta)
					changed = true
				}
			}
		}
		if !changed {
			continue
		}
		saved, err := update.Save(ctx)
		if err != nil {
			h.logger.Warn("tenant branding images not relinked", zap.String("tenant", t.Slug), zap.Error(err))
			continue
		}
		h.publishTenantLifecycleEvent(ctx, saved, "updated", "")
		h.invalidateTenantCache(ctx, saved.Slug)
		moved++
	}
	return moved, nil
}
