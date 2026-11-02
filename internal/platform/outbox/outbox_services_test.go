package outbox

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// Member events carry the member's services; anything else, a caller-set list, or an unknown
// answer leaves the payload as it was.
func TestWithUserServices(t *testing.T) {
	tenantID, userID := uuid.New(), uuid.New()
	known := true
	SetUserServices(func(_ context.Context, tid, uid uuid.UUID) ([]string, bool) {
		if tid != tenantID || uid != userID {
			t.Fatalf("looked up %s/%s, want %s/%s", tid, uid, tenantID, userID)
		}
		return []string{"pos"}, known
	})
	t.Cleanup(func() { SetUserServices(nil) })
	ctx := context.Background()

	got := withUserServices(ctx, tenantID, "auth.user", userID, "created", map[string]any{"email": "a@b"})
	if !reflect.DeepEqual(got["services"], []string{"pos"}) || got["email"] != "a@b" {
		t.Fatalf("created event: %v", got)
	}
	// The tenant may come from the payload when the event has none.
	got = withUserServices(ctx, uuid.Nil, "auth.user", userID, "pin_set", map[string]any{"tenant_id": tenantID.String()})
	if got["services"] == nil {
		t.Fatalf("pin_set event with tenant in payload: %v", got)
	}
	if got := withUserServices(ctx, tenantID, "auth.user", userID, "login", map[string]any{}); got["services"] != nil {
		t.Fatalf("login events are not member events: %v", got)
	}
	if got := withUserServices(ctx, tenantID, "auth.tenant", userID, "updated", map[string]any{}); got["services"] != nil {
		t.Fatalf("tenant events carry no member services: %v", got)
	}
	set := map[string]any{"services": []string{"inventory"}}
	if got := withUserServices(ctx, tenantID, "auth.user", userID, "updated", set); !reflect.DeepEqual(got["services"], []string{"inventory"}) {
		t.Fatalf("a caller-set list must be kept: %v", got)
	}
	known = false
	if got := withUserServices(ctx, tenantID, "auth.user", userID, "updated", map[string]any{}); got["services"] != nil {
		t.Fatalf("unknown services must be left out, never sent empty: %v", got)
	}
}
