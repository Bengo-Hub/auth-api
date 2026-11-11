package domains

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestParseRequiredFeatures(t *testing.T) {
	got := ParseRequiredFeatures(" marketflow=marketflow_custom_domain, pos = pos_custom_domain ,bad,=x,y= ")
	if len(got) != 2 || got["marketflow"] != "marketflow_custom_domain" || got["pos"] != "pos_custom_domain" {
		t.Fatalf("parsed %v", got)
	}
	if len(ParseRequiredFeatures("")) != 0 {
		t.Fatal("empty config means no gate")
	}
}

// A custom domain for an app is a plan feature (owner, 2026-11-11: MarketFlow custom domains are
// Pro and up). Apps with no required feature stay open; exempt tenants pass; a plan that cannot
// be read refuses rather than guesses.
func TestCheckPlan(t *testing.T) {
	tenant := uuid.New()
	s := &Service{}
	if err := s.CheckPlan(context.Background(), tenant, "marketflow"); err != nil {
		t.Fatalf("no gate set: %v", err)
	}

	var info PlanInfo
	var lookupErr error
	calls := 0
	s.SetPlanGate(map[string]string{"marketflow": "marketflow_custom_domain"}, func(context.Context, uuid.UUID) (PlanInfo, error) {
		calls++
		return info, lookupErr
	})

	if err := s.CheckPlan(context.Background(), tenant, "pos"); err != nil || calls != 0 {
		t.Fatalf("ungated app: %v (lookups %d)", err, calls)
	}
	info = PlanInfo{Features: []string{"marketflow_public_page"}}
	if err := s.CheckPlan(context.Background(), tenant, "marketflow"); !errors.Is(err, ErrPlanRequired) {
		t.Fatalf("lower plan: %v", err)
	}
	info = PlanInfo{Features: []string{"marketflow_custom_domain"}}
	if err := s.CheckPlan(context.Background(), tenant, "marketflow"); err != nil {
		t.Fatalf("pro plan: %v", err)
	}
	info = PlanInfo{Exempt: true}
	if err := s.CheckPlan(context.Background(), tenant, "marketflow"); err != nil {
		t.Fatalf("exempt tenant: %v", err)
	}
	lookupErr = errors.New("subscriptions down")
	if err := s.CheckPlan(context.Background(), tenant, "marketflow"); !errors.Is(err, ErrPlanUnverified) {
		t.Fatalf("lookup failure: %v", err)
	}
}
