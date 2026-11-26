package auth

import (
	"testing"
	"time"

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

// The sweep backs off and stops: it never retries a tenant forever.
func TestTrialSweepBacksOff(t *testing.T) {
	if trialBackoff(1) != trialBase || trialBackoff(2) != 2*trialBase || trialBackoff(30) != trialMax {
		t.Fatal(trialBackoff(1), trialBackoff(2), trialBackoff(30))
	}
	now := time.Now()
	if !trialDue(&ent.Tenant{Metadata: map[string]any{}}, now) {
		t.Fatal("first try")
	}
	if trialDue(&ent.Tenant{Metadata: map[string]any{metaTrialNext: now.Add(time.Hour).Format(time.RFC3339)}}, now) {
		t.Fatal("waited")
	}
	if trialDue(&ent.Tenant{Metadata: map[string]any{metaTrialAttempts: float64(trialAttempts)}}, now) {
		t.Fatal("stopped")
	}
}
