package auth

import (
	"testing"

	"github.com/bengobox/auth-api/internal/ent"
)

// The trial a tenant still waits for is the plan its sign-up chose; without one, its use case's.
func TestTrialPlanFor(t *testing.T) {
	uc := "fbo"
	if p := TrialPlanFor(&ent.Tenant{Metadata: map[string]any{MetaTrialPending: "MARKETFLOW_STARTER"}}); p != "MARKETFLOW_STARTER" {
		t.Fatal(p)
	}
	if p := TrialPlanFor(&ent.Tenant{UseCase: &uc}); p == "" {
		t.Fatal("no plan for a use case")
	}
}
