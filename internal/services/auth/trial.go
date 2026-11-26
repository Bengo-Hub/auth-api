package auth

import (
	"context"
	"strings"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/clients/subscription"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/bengobox/auth-api/internal/services/usecase"
)

// MetaTrialPending in tenant metadata is the trial plan a new organisation still has to get: the
// sign-up call to subscriptions-api failed, so it is tried again when the organisation is
// approved and by the sweep (a tenant without a plan is refused by every service; 2026-11-25).
const MetaTrialPending = "trial_plan_pending"

// TrialPlanFor is the plan a tenant's trial starts on: the one sign-up chose, else its use case's.
func TrialPlanFor(t *ent.Tenant) string {
	if p, _ := t.Metadata[MetaTrialPending].(string); strings.TrimSpace(p) != "" {
		return strings.TrimSpace(p)
	}
	uc := ""
	if t.UseCase != nil {
		uc = *t.UseCase
	}
	return usecase.TrialPlan(uc)
}

// MarkTrialPending records the plan a failed sign-up trial was for.
func MarkTrialPending(ctx context.Context, db *ent.Client, t *ent.Tenant, plan string) {
	meta := map[string]any{}
	for k, v := range t.Metadata {
		meta[k] = v
	}
	meta[MetaTrialPending] = plan
	_ = db.Tenant.UpdateOneID(t.ID).SetMetadata(meta).Exec(ctx)
}

// EnsureTrial gives a tenant with no subscription its trial. It does nothing for a tenant that has
// one, and reports whether the tenant has a plan afterwards. A failure is logged and kept for the
// sweep.
func EnsureTrial(ctx context.Context, db *ent.Client, sc *subscription.Client, logger *zap.Logger, t *ent.Tenant) bool {
	if sc == nil || t == nil {
		return false
	}
	if t.SubscriptionID != nil && *t.SubscriptionID != "" {
		return true
	}
	plan := TrialPlanFor(t)
	sub, err := sc.CreateTrialSubscription(ctx, t.ID, plan, t.Slug, t.Name, "")
	if err != nil {
		// One made earlier, whose id never reached this row, counts as a plan.
		if strings.Contains(err.Error(), "already has a subscription") {
			clearTrialPending(ctx, db, t)
			return true
		}
		logger.Warn("trial subscription still missing", zap.String("tenant_id", t.ID.String()), zap.String("plan", plan), zap.Error(err))
		if _, ok := t.Metadata[MetaTrialPending]; !ok {
			MarkTrialPending(ctx, db, t, plan)
		}
		return false
	}
	meta := map[string]any{}
	for k, v := range t.Metadata {
		meta[k] = v
	}
	delete(meta, MetaTrialPending)
	if err := db.Tenant.UpdateOneID(t.ID).SetMetadata(meta).
		SetSubscriptionID(sub.ID.String()).SetSubscriptionPlan(sub.PlanCode).SetSubscriptionStatus(sub.Status).
		SetNillableSubscriptionExpiresAt(sub.TrialEndsAt).Exec(ctx); err != nil {
		logger.Warn("trial made, tenant row not updated", zap.String("tenant_id", t.ID.String()), zap.Error(err))
	}
	logger.Info("trial subscription provisioned", zap.String("tenant_id", t.ID.String()), zap.String("plan", sub.PlanCode))
	return true
}

func clearTrialPending(ctx context.Context, db *ent.Client, t *ent.Tenant) {
	if _, ok := t.Metadata[MetaTrialPending]; !ok {
		return
	}
	meta := map[string]any{}
	for k, v := range t.Metadata {
		meta[k] = v
	}
	delete(meta, MetaTrialPending)
	_ = db.Tenant.UpdateOneID(t.ID).SetMetadata(meta).Exec(ctx)
}

// SweepTrials tries again for every active tenant still waiting for its trial.
func SweepTrials(ctx context.Context, db *ent.Client, sc *subscription.Client, logger *zap.Logger) error {
	rows, err := db.Tenant.Query().Where(tenant.StatusEQ("active"), func(s *sql.Selector) {
		s.Where(sqljson.HasKey(tenant.FieldMetadata, sqljson.Path(MetaTrialPending)))
	}).Limit(100).All(ctx)
	if err != nil {
		return err
	}
	for _, t := range rows {
		EnsureTrial(ctx, db, sc, logger, t)
	}
	return nil
}
