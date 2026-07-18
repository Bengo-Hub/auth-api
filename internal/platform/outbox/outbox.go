// Package outbox is the single home for writing auth-api domain events to the
// transactional outbox (outbox_events), replacing the four near-identical copies
// that lived in httpapi/handlers/util.go, httpapi/handlers/outlet_handler.go,
// services/auth/service.go and cmd/seed/seed_helpers.go. The payload column holds
// the FULL shared-events envelope (Event.ToJSON()) — the outbox publisher rebuilds
// the event solely from that column, so the envelope must always be complete.
package outbox

import (
	"context"
	"fmt"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/google/uuid"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
)

// Write queues one domain event (subject {aggregateType}.{eventType}) on the outbox.
// tenantSlug is optional; pass "" when unknown. Best-effort semantics are the
// caller's choice — the error is returned, never fatal here.
func Write(ctx context.Context, client *ent.Client, tenantID uuid.UUID, aggregateType string, aggregateID uuid.UUID, eventType, tenantSlug string, data map[string]any) error {
	if client == nil {
		return fmt.Errorf("outbox: nil ent client")
	}
	event := sharedevents.NewEvent(eventType, aggregateType, aggregateID, tenantID, data)
	if tenantSlug != "" {
		event.WithTenantSlug(tenantSlug)
	}
	payload, err := event.ToJSON()
	if err != nil {
		return fmt.Errorf("outbox: marshal event %s: %w", eventType, err)
	}
	if err := client.OutboxEvent.Create().
		SetTenantID(tenantID).
		SetAggregateType(aggregateType).
		SetAggregateID(aggregateID).
		SetEventType(eventType).
		SetPayload(payload).
		SetStatus(outboxevent.StatusPENDING).
		SetAttempts(0).
		Exec(ctx); err != nil {
		return fmt.Errorf("outbox: write event %s: %w", eventType, err)
	}
	return nil
}
