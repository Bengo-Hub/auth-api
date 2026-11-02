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

// UserServicesFunc answers the services a tenant member gets (access.Resolver.MemberServices);
// ok=false means unknown.
type UserServicesFunc func(ctx context.Context, tenantID, userID uuid.UUID) (services []string, ok bool)

var userServices UserServicesFunc

// SetUserServices wires the member services lookup, once at startup. Every auth.user created,
// updated and pin_set event then carries `services`, the services that should keep a local copy of
// the user (shared auth-client EventUserServices), whichever handler wrote it.
func SetUserServices(f UserServicesFunc) { userServices = f }

// userServicesEvents are the auth.user events a service provisions a local user from.
var userServicesEvents = map[string]bool{"created": true, "updated": true, "pin_set": true}

// withUserServices adds `services` to a member event unless the caller set it. An unknown answer
// adds nothing, so consumers keep their previous behaviour.
func withUserServices(ctx context.Context, tenantID uuid.UUID, aggregateType string, userID uuid.UUID, eventType string, data map[string]any) map[string]any {
	if userServices == nil || aggregateType != "auth.user" || !userServicesEvents[eventType] {
		return data
	}
	if _, set := data["services"]; set {
		return data
	}
	if tenantID == uuid.Nil {
		if v, ok := data["tenant_id"].(string); ok {
			tenantID, _ = uuid.Parse(v)
		}
	}
	services, ok := userServices(ctx, tenantID, userID)
	if !ok {
		return data
	}
	out := make(map[string]any, len(data)+1)
	for k, v := range data {
		out[k] = v
	}
	out["services"] = services
	return out
}

// Write queues one domain event (subject {aggregateType}.{eventType}) on the outbox.
// tenantSlug is optional; pass "" when unknown. Best-effort semantics are the
// caller's choice — the error is returned, never fatal here.
func Write(ctx context.Context, client *ent.Client, tenantID uuid.UUID, aggregateType string, aggregateID uuid.UUID, eventType, tenantSlug string, data map[string]any) error {
	if client == nil {
		return fmt.Errorf("outbox: nil ent client")
	}
	data = withUserServices(ctx, tenantID, aggregateType, aggregateID, eventType, data)
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
