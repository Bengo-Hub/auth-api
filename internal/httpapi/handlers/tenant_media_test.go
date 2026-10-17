package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Bengo-Hub/httpware/objectstore"
	"go.uber.org/zap"
)

// fakeR2 is a minimal S3 endpoint for tests (PUT, GET, HEAD, DELETE of objects).
func fakeR2(t *testing.T) (map[string][]byte, string) {
	var mu sync.Mutex
	objects := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			objects[p] = b
		case http.MethodHead, http.MethodGet:
			b, ok := objects[p]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodGet {
				_, _ = w.Write(b)
			}
		case http.MethodDelete:
			delete(objects, p)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	return objects, srv.URL
}

func pngDataURI(c color.NRGBA) string {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	img.Set(1, 1, c)
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b.Bytes())
}

// Inline logos and service icons move to object storage, rows keep the public link, a rerun finds
// nothing, and a replaced logo is deleted once no tenant uses it.
func TestRelinkInlineImages(t *testing.T) {
	client := newResellerTestClient(t)
	ctx := context.Background()
	objects, endpoint := fakeR2(t)
	store, err := objectstore.New("auth", objectstore.Config{
		Endpoint: endpoint, AccessKeyID: "AK", SecretAccessKey: "SK",
		PublicBucket: "pub", PrivateBucket: "priv", PublicBaseURL: "https://media.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	SetLogoStore(store)
	t.Cleanup(func() { SetLogoStore(nil) })
	h := &AdminHandler{ent: client, logger: zap.NewNop()}

	logo := pngDataURI(color.NRGBA{255, 0, 0, 255})
	icon := pngDataURI(color.NRGBA{0, 255, 0, 255})
	ten := client.Tenant.Create().SetName("Acme").SetSlug("acme-media").SetLogoURL(logo).
		SetMetadata(map[string]any{MetadataKeyServiceBranding: map[string]any{"pos": map[string]any{"name": "Acme POS", "icon_url": icon}}}).
		SaveX(ctx)
	hosted := client.Tenant.Create().SetName("Hosted").SetSlug("hosted-media").
		SetLogoURL("https://cdn.example.com/hosted.png").SaveX(ctx)

	n, err := h.RelinkInlineImages(ctx)
	if err != nil || n != 1 {
		t.Fatalf("relink: %d %v", n, err)
	}
	got := client.Tenant.GetX(ctx, ten.ID)
	prefix := "https://media.example.com/auth/" + ten.ID.String() + "/logos/"
	if got.LogoURL == nil || !strings.HasPrefix(*got.LogoURL, prefix+"brand/") {
		t.Fatalf("logo not relinked: %v", got.LogoURL)
	}
	iconURL := brandingIcons(got.Metadata[MetadataKeyServiceBranding])
	if len(iconURL) != 1 || !strings.HasPrefix(iconURL[0], prefix+"service-icons/") {
		t.Fatalf("icon not relinked: %v", iconURL)
	}
	if len(objects) != 2 {
		t.Fatalf("expected the logo and the icon stored, got %d objects", len(objects))
	}
	if *client.Tenant.GetX(ctx, hosted.ID).LogoURL != "https://cdn.example.com/hosted.png" {
		t.Error("a hosted logo is left alone")
	}
	if n, _ := h.RelinkInlineImages(ctx); n != 0 {
		t.Errorf("rerun must find nothing, moved %d", n)
	}

	// A JPEG labelled as PNG is stored as what it is.
	var jp bytes.Buffer
	_ = jpeg.Encode(&jp, image.NewRGBA(image.Rect(0, 0, 4, 4)), nil)
	mislabelled := "data:image/png;base64," + base64.StdEncoding.EncodeToString(jp.Bytes())
	if link, err := persistImageRef(ctx, ten.ID, mislabelled, logoGroupBrand); err != nil || !strings.HasSuffix(link, ".jpg") {
		t.Errorf("mislabelled jpeg: %q %v", link, err)
	}

	// Replacing the logo frees the old file; a file another tenant still links to stays.
	oldLogo := *got.LogoURL
	newLogo, err := persistImageRef(ctx, ten.ID, pngDataURI(color.NRGBA{0, 0, 255, 255}), logoGroupBrand)
	if err != nil {
		t.Fatal(err)
	}
	client.Tenant.UpdateOneID(hosted.ID).SetLogoURL(oldLogo).ExecX(ctx)
	updated := client.Tenant.UpdateOneID(ten.ID).SetLogoURL(newLogo).SaveX(ctx)
	h.releaseTenantImages(ctx, tenantImages(got), tenantImages(updated))
	if _, ok := objects["pub/"+strings.TrimPrefix(oldLogo, "https://media.example.com/")]; !ok {
		t.Error("a logo another tenant links to must stay")
	}
	client.Tenant.UpdateOneID(hosted.ID).SetLogoURL("https://cdn.example.com/hosted.png").ExecX(ctx)
	h.releaseTenantImages(ctx, []string{oldLogo}, []string{newLogo})
	if _, ok := objects["pub/"+strings.TrimPrefix(oldLogo, "https://media.example.com/")]; ok {
		t.Error("an unused replaced logo must be deleted")
	}
}
