package domains

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenantdomain"
)

// StatusPaused is a custom domain whose plan stopped including it and whose grace ended.
// Resolve does not answer for it, so the app serves its own address; an upgrade restores it.
const StatusPaused = "paused"

// DefaultDowngradeGrace is how long a custom domain keeps working after the tenant's plan
// stopped including it (owner, 2026-11-12). DOMAINS_DOWNGRADE_GRACE overrides it.
const DefaultDowngradeGrace = 14 * 24 * time.Hour

// Downgrade notices, the last part of the event type the notifier publishes.
const (
	NoticeGrace    = "grace"
	NoticePaused   = "paused"
	NoticeRestored = "restored"
)

// DowngradeNotifier tells a business what happened to its domain: kind is a Notice* value and
// until the grace end (zero for NoticeRestored).
type DowngradeNotifier func(ctx context.Context, tenantID uuid.UUID, host, service, kind string, until time.Time)

// SetDowngrade sets the grace length and the notifier for EnforcePlans.
func (s *Service) SetDowngrade(grace time.Duration, notify DowngradeNotifier) {
	if grace <= 0 {
		grace = DefaultDowngradeGrace
	}
	s.grace, s.notify = grace, notify
}

// enforceBatch bounds one page of domains read by EnforcePlans.
const enforceBatch = 500

// EnforcePlans checks every live domain of an app that needs a plan feature against its
// tenant's plan, once per tenant. A plan without the feature starts the grace (and a notice);
// past the grace the domain is paused (and a notice); a plan with the feature again clears the
// grace and restores a paused domain. A plan that cannot be read changes nothing. Run it daily
// on one replica.
func (s *Service) EnforcePlans(ctx context.Context, now time.Time) error {
	if s.planLookup == nil || len(s.required) == 0 {
		return nil
	}
	services := make([]string, 0, len(s.required))
	for svc := range s.required {
		services = append(services, svc)
	}
	grace := s.grace
	if grace <= 0 {
		grace = DefaultDowngradeGrace
	}
	verdicts := map[uuid.UUID]map[string]error{} // tenant -> service -> CheckPlan result
	var after uuid.UUID
	for {
		q := s.ent.TenantDomain.Query().
			Where(tenantdomain.ServiceIn(services...), tenantdomain.StatusIn(StatusActive, StatusIssuing, StatusPaused)).
			Order(ent.Asc(tenantdomain.FieldID)).Limit(enforceBatch)
		if after != uuid.Nil {
			q = q.Where(tenantdomain.IDGT(after))
		}
		rows, err := q.All(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			byService := verdicts[row.TenantID]
			if byService == nil {
				byService = map[string]error{}
				verdicts[row.TenantID] = byService
			}
			verdict, seen := byService[row.Service]
			if !seen {
				verdict = s.CheckPlan(ctx, row.TenantID, row.Service)
				byService[row.Service] = verdict
			}
			s.enforceOne(ctx, row, verdict, now, grace)
		}
		if len(rows) < enforceBatch {
			return nil
		}
		after = rows[len(rows)-1].ID
	}
}

// enforceOne applies one plan verdict to one domain.
func (s *Service) enforceOne(ctx context.Context, row *ent.TenantDomain, verdict error, now time.Time, grace time.Duration) {
	upd := s.ent.TenantDomain.UpdateOne(row)
	kind, until := "", time.Time{}
	switch {
	case errors.Is(verdict, ErrPlanUnverified):
		return
	case verdict == nil:
		if row.GraceUntil == nil && row.Status != StatusPaused {
			return
		}
		upd = upd.ClearGraceUntil()
		if row.Status == StatusPaused {
			upd = upd.SetStatus(StatusActive)
			kind = NoticeRestored
		}
	case errors.Is(verdict, ErrPlanRequired):
		switch {
		case row.GraceUntil == nil:
			until = now.Add(grace)
			upd = upd.SetGraceUntil(until)
			kind = NoticeGrace
		case !now.Before(*row.GraceUntil) && row.Status != StatusPaused:
			until = *row.GraceUntil
			upd = upd.SetStatus(StatusPaused)
			kind = NoticePaused
		default:
			return
		}
	default:
		return
	}
	if err := upd.Exec(ctx); err != nil {
		s.log.Warn("tenant domains: plan check not saved", zap.String("hostname", row.Hostname), zap.Error(err))
		return
	}
	s.forget(row.Hostname)
	if kind != "" && s.notify != nil {
		s.notify(ctx, row.TenantID, row.Hostname, row.Service, kind, until)
	}
}
