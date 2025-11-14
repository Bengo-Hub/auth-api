package entitlements

import (
	"context"
	"fmt"
	"time"

	"github.com/bengobox/auth-service/internal/ent"
	"github.com/bengobox/auth-service/internal/ent/featureentitlement"
	"github.com/google/uuid"
)

// Service manages feature entitlements for tenants.
type Service struct {
	ent *ent.Client
}

func New(entClient *ent.Client) *Service {
	return &Service{ent: entClient}
}

type Entitlement struct {
	TenantID    uuid.UUID      `json:"tenant_id"`
	FeatureCode string         `json:"feature_code"`
	Limit       map[string]any `json:"limit"`
	PlanSource  string         `json:"plan_source"`
	SyncedAt    time.Time      `json:"synced_at"`
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Entitlement, error) {
	rows, err := s.ent.FeatureEntitlement.Query().
		Where(featureentitlement.TenantID(tenantID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Entitlement, 0, len(rows))
	for _, r := range rows {
		out = append(out, Entitlement{
			TenantID:    r.TenantID,
			FeatureCode: r.FeatureCode,
			Limit:       anyToMap(r.LimitJSON),
			PlanSource:  r.PlanSource,
			SyncedAt:    r.SyncedAt,
		})
	}
	return out, nil
}

func (s *Service) Upsert(ctx context.Context, e Entitlement) error {
	// naive upsert: try fetch then update, else create
	rec, err := s.ent.FeatureEntitlement.Query().
		Where(
			featureentitlement.TenantID(e.TenantID),
			featureentitlement.FeatureCode(e.FeatureCode),
		).
		Only(ctx)
	if err == nil {
		return s.ent.FeatureEntitlement.UpdateOneID(rec.ID).
			SetLimitJSON(e.Limit).
			SetPlanSource(e.PlanSource).
			SetSyncedAt(time.Now()).
			Exec(ctx)
	}
	_, err = s.ent.FeatureEntitlement.Create().
		SetTenantID(e.TenantID).
		SetFeatureCode(e.FeatureCode).
		SetLimitJSON(e.Limit).
		SetPlanSource(e.PlanSource).
		SetSyncedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("create entitlement: %w", err)
	}
	return nil
}

func anyToMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return m
}
