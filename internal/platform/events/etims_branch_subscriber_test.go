package events

import (
	"testing"

	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
)

// The republished outlet event names its outlet and tenant, and carries no status or is_hq.
func TestOutletMetadataEventCarriesIDs(t *testing.T) {
	addr := "Moi Avenue"
	o := &ent.Outlet{ID: uuid.New(), TenantID: uuid.New(), Address: &addr, Metadata: map[string]any{"etims_branch_id": "01"}}
	got := outletMetadataEvent(o)
	if got["id"] != o.ID.String() || got["outlet_id"] != o.ID.String() || got["tenant_id"] != o.TenantID.String() {
		t.Errorf("ids missing: %v", got)
	}
	if got["address"] != addr || got["metadata"] == nil {
		t.Errorf("metadata or address missing: %v", got)
	}
	for _, k := range []string{"status", "is_hq", "name"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s must not be sent on a metadata-only update", k)
		}
	}
}
