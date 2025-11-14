package usage

import (
	"context"
	"time"

	"github.com/bengobox/auth-service/internal/ent"
	"github.com/bengobox/auth-service/internal/ent/usagemetric"
	"github.com/google/uuid"
)

// Service aggregates platform usage for billing/ops.
type Service struct {
	ent *ent.Client
}

func New(entClient *ent.Client) *Service {
	return &Service{ent: entClient}
}

func (s *Service) day(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func (s *Service) increment(ctx context.Context, tenantID uuid.UUID, field string, amount int) error {
	today := s.day(time.Now().UTC())
	rec, err := s.ent.UsageMetric.Query().
		Where(
			usagemetric.TenantID(tenantID),
			usagemetric.MetricDateEQ(today),
		).Only(ctx)
	if err == nil {
		up := s.ent.UsageMetric.UpdateOneID(rec.ID)
		switch field {
		case "auth_transactions":
			up.SetAuthTransactions(rec.AuthTransactions + amount)
		case "mfa_prompts":
			up.SetMfaPrompts(rec.MfaPrompts + amount)
		case "active_users":
			up.SetActiveUsers(rec.ActiveUsers + amount)
		case "machine_tokens":
			up.SetMachineTokens(rec.MachineTokens + amount)
		}
		return up.Exec(ctx)
	}
	create := s.ent.UsageMetric.Create().
		SetTenantID(tenantID).
		SetMetricDate(today)
	switch field {
	case "auth_transactions":
		create.SetAuthTransactions(amount)
	case "mfa_prompts":
		create.SetMfaPrompts(amount)
	case "active_users":
		create.SetActiveUsers(amount)
	case "machine_tokens":
		create.SetMachineTokens(amount)
	}
	_, err = create.Save(ctx)
	return err
}

func (s *Service) IncrementAuthTransactions(ctx context.Context, tenantID uuid.UUID, amount int) error {
	if amount <= 0 {
		amount = 1
	}
	return s.increment(ctx, tenantID, "auth_transactions", amount)
}

func (s *Service) IncrementMFAPrompts(ctx context.Context, tenantID uuid.UUID, amount int) error {
	if amount <= 0 {
		amount = 1
	}
	return s.increment(ctx, tenantID, "mfa_prompts", amount)
}
