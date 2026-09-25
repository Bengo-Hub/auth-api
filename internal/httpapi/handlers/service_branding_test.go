package handlers

import "testing"

func TestMergeServiceBranding_MergesPerService(t *testing.T) {
	existing := map[string]any{
		"rider": map[string]any{"name": "Loft Riders"},
		"pos":   map[string]any{"name": "Loft Till"},
	}
	submitted := map[string]any{
		"Ordering": map[string]any{"name": "  Urban   Eats ", "theme_color": "#0F766E"},
		"pos":      nil,
	}
	got, err := mergeServiceBranding(existing, submitted)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ordering, ok := got["ordering"].(map[string]any)
	if !ok {
		t.Fatalf("ordering entry missing: %#v", got)
	}
	if ordering["name"] != "Urban Eats" || ordering["short_name"] != "Urban Eats" {
		t.Fatalf("name not normalized or short_name not derived: %#v", ordering)
	}
	if _, ok := got["pos"]; ok {
		t.Fatalf("null entry should remove the override")
	}
	if _, ok := got["rider"]; !ok {
		t.Fatalf("untouched services must be kept")
	}
}

func TestMergeServiceBranding_LongNameNoDerivedShortName(t *testing.T) {
	got, err := mergeServiceBranding(nil, map[string]any{
		"ordering": map[string]any{"name": "Alpha China Market Online"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["ordering"].(map[string]any)["short_name"]; ok {
		t.Fatalf("short_name should not be derived from a long name")
	}
}

func TestMergeServiceBranding_BlankEntryRemoves(t *testing.T) {
	got, err := mergeServiceBranding(
		map[string]any{"ordering": map[string]any{"name": "Urban Eats"}},
		map[string]any{"ordering": map[string]any{"name": "", "icon_url": ""}},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["ordering"]; ok {
		t.Fatalf("blank entry should remove the override")
	}
}

func TestMergeServiceBranding_Rejects(t *testing.T) {
	cases := map[string]any{
		"not object":  "Urban Eats",
		"bad key":     map[string]any{"Ordering App!": map[string]any{"name": "x"}},
		"bad colour":  map[string]any{"ordering": map[string]any{"theme_color": "teal"}},
		"http icon":   map[string]any{"ordering": map[string]any{"icon_url": "http://example.com/a.png"}},
		"svg script":  map[string]any{"ordering": map[string]any{"icon_url": "data:image/svg+xml;utf8,<svg><script/></svg>"}},
		"number name": map[string]any{"ordering": map[string]any{"name": 42}},
	}
	for name, submitted := range cases {
		if _, err := mergeServiceBranding(nil, submitted); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
