// Package imageutil validates and compresses tenant branding images (logos)
// submitted as data: URIs from auth-ui's BrandingTab. There is no object
// storage integration for tenant assets yet — logos are stored inline as a
// base64 data URI on the tenant row — so this is the only backstop against a
// user uploading a multi-megabyte image straight into that column, which
// bloats every /tenants/by-slug response and can crash consumers (pos-ui,
// inventory-ui, ...) that embed or cache it.
package imageutil

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
)

const (
	// MaxSourceBytes bounds the decoded size of an incoming upload, checked
	// before we ever call image.Decode, so a hostile/huge payload can't burn
	// CPU or memory decoding it.
	MaxSourceBytes = 8 * 1024 * 1024 // 8MB

	// MaxDimension is the largest width or height we keep; logos are UI chrome,
	// not hero images (BrandingTab recommends 512x128).
	MaxDimension = 512

	// MaxStoredBytes is the ceiling for the final re-encoded image bytes
	// (before base64). Comfortably fits a 512px logo at PNG best-compression.
	MaxStoredBytes = 350 * 1024 // 350KB

	// MaxPlainURLLen bounds a plain (non data:) logo URL — a hosted image URL
	// has no business being longer than this.
	MaxPlainURLLen = 2048
)

func init() {
	// Ensure gif is registered for image.Decode even though we never encode it.
	_ = gif.Decode
}

// ValidateAndCompressLogoURL normalizes a logo_url value submitted to the tenant
// update endpoint. Plain http(s) URLs are passed through (just length-checked).
// data: URIs are decoded, downscaled to fit MaxDimension, and re-encoded (PNG if
// the source may have transparency, otherwise JPEG) until they fit under
// MaxStoredBytes. Returns an error the caller can surface as 400 Bad Request.
func ValidateAndCompressLogoURL(raw string) (string, error) {
	if raw == "" {
		return "", nil // clearing the logo is always allowed
	}
	if !strings.HasPrefix(raw, "data:image/") {
		if len(raw) > MaxPlainURLLen {
			return "", fmt.Errorf("logo url too long (max %d characters)", MaxPlainURLLen)
		}
		return raw, nil
	}

	comma := strings.IndexByte(raw, ',')
	if comma < 0 {
		return "", fmt.Errorf("malformed data URI")
	}
	meta := raw[:comma]
	if !strings.Contains(meta, ";base64") {
		return "", fmt.Errorf("only base64-encoded data URIs are supported")
	}

	decoded, err := base64.StdEncoding.DecodeString(raw[comma+1:])
	if err != nil {
		return "", fmt.Errorf("invalid base64 image data: %w", err)
	}
	if len(decoded) > MaxSourceBytes {
		return "", fmt.Errorf("image too large (%.1fMB) — please upload an image under %dMB",
			float64(len(decoded))/(1024*1024), MaxSourceBytes/(1024*1024))
	}

	src, format, err := image.Decode(bytes.NewReader(decoded))
	if err != nil {
		return "", fmt.Errorf("unrecognized or corrupt image file: %w", err)
	}

	img := src
	if b := src.Bounds(); b.Dx() > MaxDimension || b.Dy() > MaxDimension {
		img = resizeBox(src, MaxDimension)
	}

	// PNG/GIF sources may carry transparency, which a JPEG re-encode would
	// destroy (flattened to a solid background) — keep those as PNG first.
	preferPNG := format == "png" || format == "gif" || hasAlpha(img)

	if preferPNG {
		if out, ok := encodePNGUnder(img, MaxStoredBytes); ok {
			return toDataURL("image/png", out), nil
		}
	}
	// Either a photographic/JPEG source, or PNG re-encoding still didn't fit —
	// fall back to JPEG, stepping quality down until it fits.
	for _, q := range []int{85, 70, 55, 40} {
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: q}); err != nil {
			return "", fmt.Errorf("encode image: %w", err)
		}
		if buf.Len() <= MaxStoredBytes {
			return toDataURL("image/jpeg", buf.Bytes()), nil
		}
	}
	return "", fmt.Errorf("could not compress image under %dKB even at %dx%d — please upload a smaller logo",
		MaxStoredBytes/1024, MaxDimension, MaxDimension)
}

func encodePNGUnder(img image.Image, limit int) ([]byte, bool) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, false
	}
	if buf.Len() > limit {
		return nil, false
	}
	return buf.Bytes(), true
}

func toDataURL(mime string, data []byte) string {
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}

func hasAlpha(img image.Image) bool {
	switch img.(type) {
	case *image.RGBA, *image.NRGBA, *image.RGBA64, *image.NRGBA64:
		b := img.Bounds()
		// Sample a handful of pixels rather than the whole image — logos are
		// either fully opaque or meaningfully transparent, rarely borderline.
		step := 1
		if w := b.Dx(); w > 64 {
			step = w / 64
		}
		for y := b.Min.Y; y < b.Max.Y; y += max(1, b.Dy()/32) {
			for x := b.Min.X; x < b.Max.X; x += step {
				if _, _, _, a := img.At(x, y).RGBA(); a < 0xffff {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// resizeBox downscales src so its longer side is maxDim, preserving aspect
// ratio, via box (area-average) sampling. Good enough for logo chrome and
// keeps the package dependency-free (no golang.org/x/image needed).
func resizeBox(src image.Image, maxDim int) image.Image {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	var nw, nh int
	if w >= h {
		nw = maxDim
		nh = int(float64(h) * float64(maxDim) / float64(w))
	} else {
		nh = maxDim
		nw = int(float64(w) * float64(maxDim) / float64(h))
	}
	if nw < 1 {
		nw = 1
	}
	if nh < 1 {
		nh = 1
	}

	dst := image.NewNRGBA(image.Rect(0, 0, nw, nh))
	for y := 0; y < nh; y++ {
		sy0 := y * h / nh
		sy1 := (y + 1) * h / nh
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for x := 0; x < nw; x++ {
			sx0 := x * w / nw
			sx1 := (x + 1) * w / nw
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var rSum, gSum, bSum, aSum, count uint64
			for sy := sy0; sy < sy1 && sy < h; sy++ {
				for sx := sx0; sx < sx1 && sx < w; sx++ {
					r, g, bl, a := src.At(b.Min.X+sx, b.Min.Y+sy).RGBA()
					rSum += uint64(r)
					gSum += uint64(g)
					bSum += uint64(bl)
					aSum += uint64(a)
					count++
				}
			}
			if count == 0 {
				count = 1
			}
			dst.Set(x, y, color.RGBA64{
				R: uint16(rSum / count), G: uint16(gSum / count), B: uint16(bSum / count), A: uint16(aSum / count),
			})
		}
	}
	return dst
}
