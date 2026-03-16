package subscription

import (
	"context"
	"fmt"
	"net/http"
	"time"

	serviceclient "github.com/Bengo-Hub/shared-service-client"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TenantSubscription represents the subscription data returned by subscription-service.
type TenantSubscription struct {
	ID                 uuid.UUID      `json:"id"`
	TenantID           uuid.UUID      `json:"tenant_id"`
	PlanCode           string         `json:"plan_code"`
	PlanName           string         `json:"plan_name"`
	Status             string         `json:"status"`
	TrialEndsAt        *time.Time     `json:"trial_ends_at"`
	CurrentPeriodStart time.Time      `json:"current_period_start"`
	CurrentPeriodEnd   time.Time      `json:"current_period_end"`
	Features           []string       `json:"features"`
	Limits             map[string]int `json:"limits"`
}

// SubscriptionPlan represents a plan from subscription-service.
type SubscriptionPlan struct {
	ID           uuid.UUID      `json:"id"`
	PlanCode     string         `json:"plan_code"`
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	BillingCycle string         `json:"billing_cycle"`
	BasePrice    float64        `json:"base_price"`
	Currency     string         `json:"currency"`
	IsActive     bool           `json:"is_active"`
	IsPublic     bool           `json:"is_public"`
	TierLimits   map[string]any `json:"tier_limits"`
}

// Client communicates with subscription-service using circuit breaker pattern.
type Client struct {
	baseURL       string
	apiKey        string
	serviceClient *serviceclient.Client
	logger        *zap.Logger
}

// Config holds client configuration.
type Config struct {
	BaseURL string
	APIKey  string
	Timeout time.Duration
}

// NewClient creates a new subscription service client with circuit breaker.
func NewClient(cfg Config, logger *zap.Logger) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Configure service client with circuit breaker
	scCfg := serviceclient.DefaultConfig(
		cfg.BaseURL,
		"auth-service",
		logger.Named("subscription.client"),
	)
	scCfg.Timeout = timeout

	return &Client{
		baseURL:       cfg.BaseURL,
		apiKey:        cfg.APIKey,
		serviceClient: serviceclient.New(scCfg),
		logger:        logger.Named("subscription.client"),
	}
}

// GetTenantSubscription fetches subscription data for a tenant.
// Returns nil if subscription not found (tenant may not have a subscription yet).
func (c *Client) GetTenantSubscription(ctx context.Context, tenantID uuid.UUID) (*TenantSubscription, error) {
	path := fmt.Sprintf("/api/v1/tenants/%s/subscription", tenantID.String())

	headers := make(map[string]string)
	if c.apiKey != "" {
		headers["X-API-Key"] = c.apiKey
	}

	resp, err := c.serviceClient.Get(ctx, path, headers)
	if err != nil {
		c.logger.Warn("subscription service request failed",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("http request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		// Tenant has no subscription - not an error
		c.logger.Debug("no subscription found for tenant",
			zap.String("tenant_id", tenantID.String()),
		)
		return nil, nil
	}

	if !resp.IsSuccess() {
		var errBody map[string]any
		_ = resp.DecodeJSON(&errBody)
		c.logger.Warn("subscription service returned error",
			zap.String("tenant_id", tenantID.String()),
			zap.Int("status", resp.StatusCode),
			zap.Any("error", errBody),
		)
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var sub TenantSubscription
	if err := resp.DecodeJSON(&sub); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	c.logger.Debug("fetched tenant subscription",
		zap.String("tenant_id", tenantID.String()),
		zap.String("plan_code", sub.PlanCode),
		zap.String("status", sub.Status),
	)

	return &sub, nil
}
// CreateTrialSubscription provisions a new trial subscription for a tenant.
func (c *Client) CreateTrialSubscription(ctx context.Context, tenantID uuid.UUID, planCode string) (*TenantSubscription, error) {
	path := "/api/v1/subscription"

	reqBody := map[string]any{
		"tenant_id":  tenantID.String(),
		"plan_code":  planCode,
		"trial_days": 14, // Default trial period
	}

	headers := make(map[string]string)
	if c.apiKey != "" {
		headers["X-API-Key"] = c.apiKey
	}
	// For subscription-api, we should also pass the tenant context if required
	headers["X-Tenant-ID"] = tenantID.String()

	resp, err := c.serviceClient.Post(ctx, path, reqBody, headers)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	if !resp.IsSuccess() {
		var errBody map[string]any
		_ = resp.DecodeJSON(&errBody)
		return nil, fmt.Errorf("unexpected status %d: %v", resp.StatusCode, errBody)
	}

	var sub TenantSubscription
	if err := resp.DecodeJSON(&sub); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &sub, nil
}

// GetPlanByCode fetches a subscription plan details by its unique code.
func (c *Client) GetPlanByCode(ctx context.Context, code string) (*SubscriptionPlan, error) {
	path := fmt.Sprintf("/api/v1/plans/code/%s", code)

	headers := make(map[string]string)
	if c.apiKey != "" {
		headers["X-API-Key"] = c.apiKey
	}

	resp, err := c.serviceClient.Get(ctx, path, headers)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("plan not found: %s", code)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var wrapper struct {
		Plan *SubscriptionPlan `json:"plan"`
	}
	if err := resp.DecodeJSON(&wrapper); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return wrapper.Plan, nil
}
