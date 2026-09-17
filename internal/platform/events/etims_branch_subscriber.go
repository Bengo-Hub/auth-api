package events

import (
	"context"
	"encoding/json"
	"time"

	eventslib "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outlet"
	"github.com/bengobox/auth-api/internal/platform/outbox"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// EtimsBranchSubscriber keeps an outlet's metadata.etims_branch_id in sync with the KRA branch
// treasury-api actually registered a real fiscal device under. auth-api's Outlet already carries
// a free-form metadata JSON map, so this needs no new schema field: it is the shared label other
// services (inventory-api, pos-api, treasury-api itself) can read to know which outlet maps to
// which KRA branch, without each needing its own copy of treasury-api's EtimsDevice.
//
// treasury-api is the sole originator of this fact (a branch_id is tied to a physical device's
// real OSCU registration with KRA, not something auth-api can independently know), so this
// consumer only ever applies what treasury-api reports — it never invents or guesses a value.
// The merge is idempotent (a no-op when the value already matches) and re-publishes
// auth.outlet.updated afterward so any other existing outlet mirror picks up the change through
// its normal event path — completing the two-way sync started by treasury-api's
// OutletBranchSubscriber, which watches this same auth.outlet.updated event in the other
// direction to flag drift against its own registered device.
type EtimsBranchSubscriber struct {
	entClient *ent.Client
	logger    *zap.Logger
	sub       *nats.Subscription
}

func NewEtimsBranchSubscriber(entClient *ent.Client, logger *zap.Logger) *EtimsBranchSubscriber {
	return &EtimsBranchSubscriber{entClient: entClient, logger: logger.Named("etims-branch.subscriber")}
}

// Start subscribes to treasury.etims.branch_assigned on the provided NATS connection.
// Returns immediately; messages are processed asynchronously.
func (s *EtimsBranchSubscriber) Start(conn *nats.Conn) error {
	sub, err := eventslib.QueueSubscribe(s.logger, conn, "treasury.etims.branch_assigned", "auth-etims-branch", s.handle)
	if err != nil {
		return err
	}
	s.sub = sub
	s.logger.Info("subscribed to treasury.etims.branch_assigned")
	return nil
}

// Stop drains the NATS subscription.
func (s *EtimsBranchSubscriber) Stop() {
	if s.sub != nil {
		_ = s.sub.Drain()
	}
}

type branchAssignedPayload struct {
	TenantID string `json:"tenant_id"`
	OutletID string `json:"outlet_id"`
	BranchID string `json:"branch_id"`
}

func (s *EtimsBranchSubscriber) handle(msg *nats.Msg) {
	var wrapper struct {
		Payload  branchAssignedPayload `json:"payload"`
		TenantID string                `json:"tenant_id"`
	}
	if err := json.Unmarshal(msg.Data, &wrapper); err != nil {
		s.logger.Warn("failed to parse etims.branch_assigned event", zap.Error(err))
		return
	}

	tenantIDStr := wrapper.TenantID
	if tenantIDStr == "" {
		tenantIDStr = wrapper.Payload.TenantID
	}
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil || tenantID == uuid.Nil {
		s.logger.Warn("etims.branch_assigned event missing a valid tenant_id, skipping")
		return
	}
	outletID, err := uuid.Parse(wrapper.Payload.OutletID)
	if err != nil || outletID == uuid.Nil {
		s.logger.Warn("etims.branch_assigned event missing a valid outlet_id, skipping",
			zap.String("tenant_id", tenantIDStr))
		return
	}
	if wrapper.Payload.BranchID == "" {
		s.logger.Warn("etims.branch_assigned event missing branch_id, skipping",
			zap.String("tenant_id", tenantIDStr), zap.String("outlet_id", wrapper.Payload.OutletID))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	o, err := s.entClient.Outlet.Query().Where(outlet.ID(outletID), outlet.TenantID(tenantID)).Only(ctx)
	if err != nil {
		s.logger.Warn("etims.branch_assigned: outlet not found",
			zap.String("tenant_id", tenantIDStr), zap.String("outlet_id", wrapper.Payload.OutletID), zap.Error(err))
		return
	}
	if existing, _ := o.Metadata["etims_branch_id"].(string); existing == wrapper.Payload.BranchID {
		return // already in sync — idempotent no-op, matches every redelivery
	}

	merged := make(map[string]any, len(o.Metadata)+1)
	for k, v := range o.Metadata {
		merged[k] = v
	}
	merged["etims_branch_id"] = wrapper.Payload.BranchID

	updated, err := s.entClient.Outlet.UpdateOne(o).SetMetadata(merged).Save(ctx)
	if err != nil {
		s.logger.Warn("etims.branch_assigned: failed to update outlet metadata",
			zap.String("tenant_id", tenantIDStr), zap.String("outlet_id", wrapper.Payload.OutletID), zap.Error(err))
		return
	}

	eventData := map[string]any{"metadata": updated.Metadata}
	if updated.Address != nil && *updated.Address != "" {
		eventData["address"] = *updated.Address
	}
	if err := outbox.Write(ctx, s.entClient, tenantID, "auth.outlet", outletID, "updated", "", eventData); err != nil {
		s.logger.Warn("etims.branch_assigned: failed to republish auth.outlet.updated", zap.Error(err))
	}

	s.logger.Info("outlet metadata synced with treasury-api's registered eTIMS branch",
		zap.String("tenant_id", tenantIDStr), zap.String("outlet_id", wrapper.Payload.OutletID),
		zap.String("branch_id", wrapper.Payload.BranchID))
}
