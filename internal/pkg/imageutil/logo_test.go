package imageutil

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

// oversizedPNGDataURL synthesizes a large PNG data URI at realistic logo
// dimensions (matching a real incident: a 1408x768 upload that landed on a
// tenant record as a 2.65MB data URI and crashed consumers rendering it). A
// smooth gradient, not noise, mirrors real photo/logo content — this is a
// resize/dimension test, not a codec-entropy stress test.
func oversizedPNGDataURL(t *testing.T, w, h int) string {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.NRGBA{
				R: uint8(x % 256), G: uint8(y % 256), B: uint8((x + y) % 256), A: 255,
			})
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.NoCompression}
	if err := enc.Encode(&buf, img); err != nil {
		t.Fatalf("encode fixture png: %v", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestValidateAndCompressLogoURL_OversizedPNG(t *testing.T) {
	dataURL := oversizedPNGDataURL(t, 1408, 768)
	t.Logf("input size: %d bytes", len(dataURL))
	if len(dataURL) < MaxStoredBytes*2 {
		t.Fatalf("fixture not large enough to exercise compression: %d bytes", len(dataURL))
	}

	out, err := ValidateAndCompressLogoURL(dataURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("output size: %d bytes", len(out))
	if len(out) >= len(dataURL) {
		t.Fatalf("expected compression, output (%d) not smaller than input (%d)", len(out), len(dataURL))
	}
	if !strings.HasPrefix(out, "data:image/") {
		t.Fatalf("expected a data URI, got prefix %q", out[:min(30, len(out))])
	}
	comma := strings.IndexByte(out, ',')
	decoded, err := base64.StdEncoding.DecodeString(out[comma+1:])
	if err != nil {
		t.Fatalf("output not valid base64: %v", err)
	}
	if len(decoded) > MaxStoredBytes {
		t.Fatalf("decoded output %d bytes exceeds MaxStoredBytes %d", len(decoded), MaxStoredBytes)
	}
}

func TestValidateAndCompressLogoURL_PlainURL(t *testing.T) {
	u := "https://example.com/logo.png"
	out, err := ValidateAndCompressLogoURL(u)
	if err != nil || out != u {
		t.Fatalf("expected passthrough, got %q err=%v", out, err)
	}
}

func TestValidateAndCompressLogoURL_Empty(t *testing.T) {
	out, err := ValidateAndCompressLogoURL("")
	if err != nil || out != "" {
		t.Fatalf("expected clean clear, got %q err=%v", out, err)
	}
}
