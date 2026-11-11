package domains

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Plan gate (owner, 2026-11-11): a custom domain for an app can be a plan feature, e.g.
// MarketFlow custom domains are Pro and up (feature marketflow_custom_domain). Which app needs
// which feature comes from config (DOMAINS_REQUIRED_FEATURES), never code; an app with no entry
// stays open to every plan, as before.

var (
	ErrPlanRequired   = errors.New("custom domains for this app are not on your plan; upgrade to add one")
	ErrPlanUnverified = errors.New("your plan could not be checked right now; try again shortly")
)

// PlanInfo is what the gate needs from subscriptions: whether the tenant is exempt from gating
// (platform, demo) and the plan's feature codes.
type PlanInfo struct {
	Exempt   bool
	Features []string
}

// PlanLookup reads a tenant's plan.
type PlanLookup func(ctx context.Context, tenantID uuid.UUID) (PlanInfo, error)

// ParseRequiredFeatures reads "service=feature,service=feature"; malformed pairs are skipped.
func ParseRequiredFeatures(raw string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if ok && k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

// SetPlanGate turns the plan check on (call once at startup).
func (s *Service) SetPlanGate(required map[string]string, lookup PlanLookup) {
	s.required, s.planLookup = required, lookup
}

// CheckPlan reports whether the tenant's plan allows a custom domain for the service.
func (s *Service) CheckPlan(ctx context.Context, tenantID uuid.UUID, service string) error {
	feature := s.required[service]
	if feature == "" || s.planLookup == nil {
		return nil
	}
	info, err := s.planLookup(ctx, tenantID)
	if err != nil {
		if s.log != nil {
			s.log.Warn("tenant domains: plan lookup failed", zap.String("tenant_id", tenantID.String()), zap.Error(err))
		}
		return ErrPlanUnverified
	}
	if info.Exempt || slices.Contains(info.Features, feature) {
		return nil
	}
	return ErrPlanRequired
}
