package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/tenant"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// SubscriptionSubscriber listens for tenant.subscription.updated events and
// keeps auth-api's denormalised subscription cache in sync so that new JWTs
// always carry the current plan and status without a round-trip to subscription-api.
type SubscriptionSubscriber struct {
	entClient *ent.Client
	redis     *redis.Client
	namespace string
	logger    *zap.Logger
	sub       *nats.Subscription
}

// NewSubscriptionSubscriber creates a new subscriber. namespace is the Redis key
// prefix used by this service (e.g. "auth").
func NewSubscriptionSubscriber(entClient *ent.Client, redis *redis.Client, namespace string, logger *zap.Logger) *SubscriptionSubscriber {
	return &SubscriptionSubscriber{
		entClient: entClient,
		redis:     redis,
		namespace: namespace,
		logger:    logger.Named("subscription.subscriber"),
	}
}

// Start subscribes to tenant.subscription.updated on the provided NATS connection.
// Returns immediately; messages are processed asynchronously.
func (s *SubscriptionSubscriber) Start(conn *nats.Conn) error {
	sub, err := conn.Subscribe("tenant.subscription.updated", s.handle)
	if err != nil {
		return err
	}
	s.sub = sub
	s.logger.Info("subscribed to tenant.subscription.updated")
	return nil
}

// Stop drains the NATS subscription.
func (s *SubscriptionSubscriber) Stop() {
	if s.sub != nil {
		_ = s.sub.Drain()
	}
}

type subscriptionUpdatedPayload struct {
	TenantID    string `json:"tenant_id"`
	TenantSlug  string `json:"tenant_slug"`
	NewPlanCode string `json:"new_plan_code"`
	NewPlanName string `json:"new_plan_name"`
	Direction   string `json:"direction"`
}

func (s *SubscriptionSubscriber) handle(msg *nats.Msg) {
	var wrapper struct {
		Payload map[string]interface{} `json:"payload"`
		TenantID string                 `json:"tenant_id"`
		TenantSlug string               `json:"tenant_slug,omitempty"`
	}
	if err := json.Unmarshal(msg.Data, &wrapper); err != nil {
		s.logger.Warn("failed to parse subscription.updated event", zap.Error(err))
		return
	}

	// Extract tenant_id and slug — prefer top-level fields, fall back to payload.
	tenantIDStr := wrapper.TenantID
	if tenantIDStr == "" {
		if v, ok := wrapper.Payload["tenant_id"].(string); ok {
			tenantIDStr = v
		}
	}
	tenantSlug := wrapper.TenantSlug
	if tenantSlug == "" {
		if v, ok := wrapper.Payload["tenant_slug"].(string); ok {
			tenantSlug = v
		}
	}
	newPlanCode, _ := wrapper.Payload["new_plan_code"].(string)

	if tenantIDStr == "" && tenantSlug == "" {
		s.logger.Warn("subscription.updated event missing tenant_id and tenant_slug, skipping")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Look up tenant
	var tenantEntity *ent.Tenant
	var err error
	if tenantIDStr != "" {
		tenantID, parseErr := uuid.Parse(tenantIDStr)
		if parseErr == nil {
			tenantEntity, err = s.entClient.Tenant.Get(ctx, tenantID)
		}
	}
	if tenantEntity == nil && tenantSlug != "" {
		tenantEntity, err = s.entClient.Tenant.Query().Where(tenant.SlugEQ(tenantSlug)).Only(ctx)
	}
	if err != nil || tenantEntity == nil {
		s.logger.Warn("subscription.updated: tenant not found",
			zap.String("tenant_id", tenantIDStr),
			zap.String("tenant_slug", tenantSlug),
			zap.Error(err),
		)
		return
	}

	// Update denormalised subscription fields so future JWTs carry the new plan
	upd := s.entClient.Tenant.UpdateOne(tenantEntity)
	if newPlanCode != "" {
		upd = upd.SetSubscriptionPlan(newPlanCode)
		upd = upd.SetSubscriptionStatus("ACTIVE")
	}
	if _, err = upd.Save(ctx); err != nil {
		s.logger.Warn("subscription.updated: failed to update tenant subscription cache",
			zap.String("tenant_slug", tenantEntity.Slug),
			zap.Error(err),
		)
		return
	}

	// Invalidate the shared tenant branding cache so downstream services that
	// cache tenant metadata also pick up any plan-driven changes.
	if s.redis != nil && tenantEntity.Slug != "" {
		cacheKey := "tenant:" + tenantEntity.Slug
		if err := s.redis.Del(ctx, cacheKey).Err(); err != nil {
			s.logger.Warn("subscription.updated: failed to delete tenant cache",
				zap.String("key", cacheKey),
				zap.Error(err),
			)
		} else {
			s.logger.Debug("invalidated tenant cache", zap.String("key", cacheKey))
		}
	}

	s.logger.Info("tenant subscription cache updated",
		zap.String("tenant_slug", tenantEntity.Slug),
		zap.String("new_plan_code", newPlanCode),
	)
}
