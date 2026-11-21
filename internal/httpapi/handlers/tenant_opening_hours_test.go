package handlers

import (
	"reflect"
	"testing"
)

func TestNormalizeTenantOpeningHours(t *testing.T) {
	got, err := normalizeTenantOpeningHours(map[string]any{
		"Monday":   map[string]any{"open": "7:30", "close": "22:30"},
		"saturday": []any{map[string]any{"open": "08:00", "close": "14:00"}, map[string]any{"open": "17:00", "close": "01:00"}},
		"sunday":   nil,
	})
	if err != nil {
		t.Fatalf("valid schedule refused: %v", err)
	}
	want := map[string]any{
		"monday":   map[string]any{"open": "07:30", "close": "22:30"},
		"saturday": []any{map[string]any{"open": "08:00", "close": "14:00"}, map[string]any{"open": "17:00", "close": "01:00"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	bad := []any{
		"07:30-22:30",
		map[string]any{"funday": map[string]any{"open": "07:30", "close": "22:30"}},
		map[string]any{"monday": map[string]any{"open": "25:00", "close": "22:30"}},
		map[string]any{"monday": map[string]any{"open": "07:3", "close": "22:30"}},
		map[string]any{"monday": map[string]any{"open": "07:30", "close": "07:30"}},
		map[string]any{"monday": map[string]any{"open": "07:30", "close": "22:30", "note": "x"}},
		map[string]any{"monday": map[string]any{"open": "07:30"}},
	}
	for _, b := range bad {
		if _, err := normalizeTenantOpeningHours(b); err == nil {
			t.Errorf("accepted %v", b)
		}
	}

	if got, err := normalizeTenantOpeningHours(map[string]any{}); err != nil || got != nil {
		t.Errorf("empty schedule: got %v, %v; want nil, nil", got, err)
	}
}

func TestApplyTenantOpeningHoursMetadata(t *testing.T) {
	meta := map[string]any{}
	if err := applyTenantOpeningHoursMetadata(meta, map[string]any{"monday": map[string]any{"open": "07:30", "close": "22:30"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := meta[MetadataKeyOpeningHours]; !ok {
		t.Fatal("valid schedule not stored")
	}
	if err := applyTenantOpeningHoursMetadata(meta, "bad"); err == nil {
		t.Fatal("bad schedule accepted")
	}
	if _, ok := meta[MetadataKeyOpeningHours]; !ok {
		t.Fatal("a refused value cleared the stored schedule")
	}
	if err := applyTenantOpeningHoursMetadata(meta, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := meta[MetadataKeyOpeningHours]; ok {
		t.Fatal("null did not clear the schedule")
	}
	if got := tenantOpeningHoursPayload(nil); len(got) != 0 {
		t.Fatalf("unset payload = %v, want empty", got)
	}
}
