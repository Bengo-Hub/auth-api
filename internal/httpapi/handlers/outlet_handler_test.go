package handlers

import "testing"

// TestRestrictFacilityTypeMetadata guards against a real gap found live 2026-09-02: an ordinary
// tenant-admin-equivalent role (not just platform staff) could set/change an outlet's
// metadata.facility_type — which drives hospital-ui's whole adaptive sidebar — to a richer tier
// than the tenant actually subscribes to, with nothing to stop or flag the mismatch.
func TestRestrictFacilityTypeMetadata(t *testing.T) {
	t.Run("platform owner may set it", func(t *testing.T) {
		meta := map[string]any{"facility_type": "hospital"}
		restrictFacilityTypeMetadata(true, meta, "")
		if meta["facility_type"] != "hospital" {
			t.Errorf("platform owner's facility_type was stripped: %v", meta)
		}
	})

	t.Run("platform owner may change an existing value", func(t *testing.T) {
		meta := map[string]any{"facility_type": "facility"}
		restrictFacilityTypeMetadata(true, meta, "chemist")
		if meta["facility_type"] != "facility" {
			t.Errorf("platform owner's new value was overwritten: %v", meta)
		}
	})

	t.Run("tenant admin cannot set it on a new outlet", func(t *testing.T) {
		meta := map[string]any{"facility_type": "hospital", "screensaver_url": "https://x"}
		restrictFacilityTypeMetadata(false, meta, "")
		if _, ok := meta["facility_type"]; ok {
			t.Errorf("tenant admin's facility_type was not stripped: %v", meta)
		}
		if meta["screensaver_url"] != "https://x" {
			t.Errorf("unrelated metadata was incorrectly dropped: %v", meta)
		}
	})

	t.Run("tenant admin cannot change an existing value, and it is preserved not wiped", func(t *testing.T) {
		meta := map[string]any{"facility_type": "hospital"}
		restrictFacilityTypeMetadata(false, meta, "chemist")
		if meta["facility_type"] != "chemist" {
			t.Errorf("tenant admin's attempted value was not reverted to the real one: got %v, want chemist", meta["facility_type"])
		}
	})

	t.Run("tenant admin editing other fields does not silently wipe a platform-set value", func(t *testing.T) {
		meta := map[string]any{"pin_login_message": "Welcome"}
		restrictFacilityTypeMetadata(false, meta, "facility")
		if meta["facility_type"] != "facility" {
			t.Errorf("existing facility_type was wiped by an unrelated metadata update: %v", meta)
		}
	})

	t.Run("nil metadata is a no-op", func(t *testing.T) {
		restrictFacilityTypeMetadata(false, nil, "chemist") // must not panic
	})
}
