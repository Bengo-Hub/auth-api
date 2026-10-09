package handlers

import "testing"

func f(v float64) *float64 { return &v }

func TestApplyOutletPin(t *testing.T) {
	existing := map[string]any{"latitude": 0.4545662, "longitude": 34.1272854, "facility_type": "x"}

	// No metadata and no pin: nothing to write.
	if md, err := applyOutletPin(nil, existing, nil, nil); err != nil || md != nil {
		t.Fatalf("want no change, got %v %v", md, err)
	}
	// Pin only: existing metadata kept, pin replaced.
	md, err := applyOutletPin(nil, existing, f(0.5), f(34.2))
	if err != nil || md["latitude"] != 0.5 || md["longitude"] != 34.2 || md["facility_type"] != "x" {
		t.Fatalf("pin only = %v %v", md, err)
	}
	if existing["latitude"] != 0.4545662 {
		t.Fatal("existing map must not be mutated")
	}
	// Metadata replace without a pin keeps the stored pin.
	md, err = applyOutletPin(map[string]any{"contact_phones": []any{}}, existing, nil, nil)
	if err != nil || md["latitude"] != 0.4545662 || md["longitude"] != 34.1272854 {
		t.Fatalf("pin must survive a metadata replace: %v", md)
	}
	// Invalid pins.
	for _, c := range []struct{ lat, lng *float64 }{{f(1), nil}, {f(91), f(1)}, {f(1), f(181)}, {f(0), f(0)}} {
		if _, err := applyOutletPin(nil, existing, c.lat, c.lng); err == nil {
			t.Errorf("pin %v,%v should be rejected", c.lat, c.lng)
		}
	}
	lat, lng := outletPin(existing)
	if lat == nil || *lng != 34.1272854 {
		t.Fatal("outletPin read failed")
	}
	if a, b := outletPin(map[string]any{"latitude": "x"}); a != nil || b != nil {
		t.Fatal("non-numeric pin must be ignored")
	}
}
