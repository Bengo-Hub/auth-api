package subscription

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	serviceclient "github.com/Bengo-Hub/shared-service-client"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// KeyProviderFunc is a function that returns the current API key.
// It is called per-request so that key rotations take effect without restart.
type KeyProviderFunc func(ctx context.Context) string

// TenantSubscription represents the subscription data returned by subscription-service.
type TenantSubscription struct {
	ID       uuid.UUID `json:"id"`
	TenantID uuid.UUID `json:"tenant_id"`
	PlanCode string    `json:"plan_code"`
	PlanName string    `json:"plan_name"`
	// TierOrder is the resolved plan's tier rank (1=Starter,2=Growth,3=Professional; higher for
	// licenses). Minted into the JWT sub_tier claim for backend tier-aware gating.
	TierOrder          int            `json:"tier_order"`
	Status             string         `json:"status"`
	TrialEndsAt        *time.Time     `json:"trial_ends_at"`
	CurrentPeriodStart time.Time      `json:"current_period_start"`
	CurrentPeriodEnd   time.Time      `json:"current_period_end"`
	Features           []string       `json:"features"`
	Limits             map[string]int `json:"limits"`
	// ActiveProducts is the product_code of every currently-active per-product subscription
	// line — minted into the JWT active_products claim so the app-switcher can show only
	// activated apps without an extra network call.
	ActiveProducts []string `json:"active_products"`
	// Scenario resolution from subscription-service. BillingMode is one of
	// "recurring" | "one_time" | "service_charge"; IsPerpetual marks a paid
	// one-time licence that must never expire (JWT omits expiry for these).
	BillingCycle string `json:"billing_cycle"`
	BillingMode  string `json:"billing_mode"`
	PlanType     string `json:"plan_type"`
	IsPerpetual  bool   `json:"is_perpetual"`
	// AllowOverage is the tenant's opt-in extra-usage master switch (pay-as-you-go).
	AllowOverage bool `json:"allow_overage"`
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
	baseURL     string
	keyProvider KeyProviderFunc // resolves API key at call time (supports rotation)
	// Fallback static key (env var). Used when keyProvider is nil or returns "".
	fallbackKey   string
	serviceClient *serviceclient.Client
	logger        *zap.Logger

	// In-memory key cache: key provider may be expensive, cache for keyTTL.
	mu        sync.Mutex
	cachedKey string
	keyExpiry time.Time
	keyTTL    time.Duration
}

// Config holds client configuration.
type Config struct {
	BaseURL     string
	APIKey      string          // static fallback (env var). Used when KeyProvider is nil or returns "".
	KeyProvider KeyProviderFunc // optional dynamic key resolver (DB lookup)
	Timeout     time.Duration
	KeyCacheTTL time.Duration // how long to cache the resolved key (default 5m)
}

// NewClient creates a new subscription service client with circuit breaker.
func NewClient(cfg Config, logger *zap.Logger) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	cacheTTL := cfg.KeyCacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
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
		keyProvider:   cfg.KeyProvider,
		fallbackKey:   cfg.APIKey,
		serviceClient: serviceclient.New(scCfg),
		logger:        logger.Named("subscription.client"),
		keyTTL:        cacheTTL,
	}
}

// resolveKey returns the current API key. Checks in-memory cache first,
// then calls keyProvider (DB lookup), then falls back to static env key.
func (c *Client) resolveKey(ctx context.Context) string {
	if c.keyProvider == nil {
		return c.fallbackKey
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedKey != "" && time.Now().Before(c.keyExpiry) {
		return c.cachedKey
	}

	key := c.keyProvider(ctx)
	if key == "" {
		key = c.fallbackKey
	}
	if key != "" {
		c.cachedKey = key
		c.keyExpiry = time.Now().Add(c.keyTTL)
	}
	return key
}

// GetTenantSubscription fetches subscription data for a tenant.
// Returns nil if subscription not found (tenant may not have a subscription yet).
func (c *Client) GetTenantSubscription(ctx context.Context, tenantID uuid.UUID) (*TenantSubscription, error) {
	// include_usage=false skips subscription-service's per-tenant usage_events
	// aggregate — JWT enrichment only needs plan/features/limits/status, not the
	// current-month usage counters, so we keep the login path off that query.
	path := fmt.Sprintf("/api/v1/tenants/%s/subscription?include_usage=false", tenantID.String())

	headers := make(map[string]string)
	if key := c.resolveKey(ctx); key != "" {
		headers["X-API-Key"] = key
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
// slug and name seed the subscription service's local tenant projection on demand,
// so provisioning at signup does not race the async auth.tenant.created sync.
func (c *Client) CreateTrialSubscription(ctx context.Context, tenantID uuid.UUID, planCode, slug, name string) (*TenantSubscription, error) {
	path := "/api/v1/subscription"

	reqBody := map[string]any{
		"tenant_id":   tenantID.String(),
		"plan_code":   planCode,
		"trial_days":  14, // Default trial period
		"tenant_slug": slug,
		"tenant_name": name,
	}

	headers := make(map[string]string)
	if key := c.resolveKey(ctx); key != "" {
		headers["X-API-Key"] = key
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
	if key := c.resolveKey(ctx); key != "" {
		headers["X-API-Key"] = key
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
