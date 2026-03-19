package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bengobox/auth-api/internal/crypto"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/integrationconfig"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"entgo.io/ent/dialect/sql"
)

// Service handles integration configurations with encrypted storage and caching.
type Service struct {
	client        *ent.Client
	redis         *redis.Client
	encryptionKey string // AES hex key hex
	apiBaseURL    string // Base URL for callback generation
}

// New creates a new integration service.
func New(client *ent.Client, redis *redis.Client, encryptionKey, apiBaseURL string) *Service {
	return &Service{
		client:        client,
		redis:         redis,
		encryptionKey: encryptionKey,
		apiBaseURL:    apiBaseURL,
	}
}

// Initialize bootstraps the encryption key from DB, ENV, or auto-generation.
func (s *Service) Initialize(ctx context.Context) error {
	// 1. Try to load from DB
	config, err := s.client.IntegrationConfig.Query().
		Where(integrationconfig.Name("system_encryption_key"), integrationconfig.TenantIDIsNil()).
		Only(ctx)

	if err == nil {
		// Found in DB, use it
		s.encryptionKey = config.EncryptedCredentials
		return nil
	}

	// 2. Not in DB, check if we have it from ENV (passed via New)
	if s.encryptionKey != "" {
		// Save to DB for next time
		return s.saveMasterKey(ctx, s.encryptionKey)
	}

	// 3. Generate new key
	newKey, err := crypto.GenerateRandomKey(256)
	if err != nil {
		return err
	}
	s.encryptionKey = newKey
	return s.saveMasterKey(ctx, newKey)
}

func (s *Service) saveMasterKey(ctx context.Context, key string) error {
	return s.client.IntegrationConfig.Create().
		SetName("system_encryption_key").
		SetDisplayName("System Encryption Key").
		SetDescription("Master key for secret management. DO NOT DELETE.").
		SetEncryptedCredentials(key). // Stored as-is in this special case
		SetIsActive(true).
		SetStatus("active").
		OnConflict(sql.ConflictColumns(integrationconfig.FieldTenantID, integrationconfig.FieldName)).
		UpdateNewValues().
		Exec(ctx)
}

// GetDecryptedConfig retrieves credentials for a service, using Redis cache if available.
func (s *Service) GetDecryptedConfig(ctx context.Context, tenantID *uuid.UUID, name string) (map[string]string, error) {
	cacheKey := s.getCacheKey(tenantID, name)

	// 1. Try Redis Cache (Decrypted value is cached for 24h as per requirement)
	val, err := s.redis.Get(ctx, cacheKey).Result()
	if err == nil {
		var creds map[string]string
		if err := json.Unmarshal([]byte(val), &creds); err == nil {
			return creds, nil
		}
	}

	// 2. Fetch from DB
	query := s.client.IntegrationConfig.Query().Where(integrationconfig.Name(name))
	if tenantID != nil {
		query = query.Where(integrationconfig.TenantIDEQ(*tenantID))
	} else {
		query = query.Where(integrationconfig.TenantIDIsNil())
	}

	config, err := query.Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("integration config %s not found: %w", name, err)
	}

	if !config.IsActive {
		return nil, fmt.Errorf("integration %s is disabled", name)
	}

	// 3. Decrypt (AES-GCM encrypted by SaveConfig / auth-ui)
	decrypted, err := crypto.Decrypt(config.EncryptedCredentials, s.encryptionKey)
	if err != nil {
		// Fallback: seeder stores credentials as plain JSON before the first
		// auth-ui save re-encrypts them. Accept plain JSON transparently.
		var rawCreds map[string]string
		if jsonErr := json.Unmarshal([]byte(config.EncryptedCredentials), &rawCreds); jsonErr == nil {
			return rawCreds, nil
		}
		return nil, fmt.Errorf("decrypt credentials for %s: %w", name, err)
	}

	var creds map[string]string
	if err := json.Unmarshal([]byte(decrypted), &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials for %s: %w", name, err)
	}

	// 4. Resolve dynamic fields (like callback URLs) if missing
	if _, exists := creds["redirect_url"]; !exists && s.apiBaseURL != "" {
		creds["redirect_url"] = fmt.Sprintf("%s/api/v1/auth/oauth/%s/callback", s.apiBaseURL, name)
	}

	// 5. Cache in Redis for 24h
	credsJSON, _ := json.Marshal(creds)
	s.redis.Set(ctx, cacheKey, credsJSON, 24*time.Hour)

	return creds, nil
}

// SaveConfig encrypts and stores credentials for a service.
func (s *Service) SaveConfig(ctx context.Context, tenantID *uuid.UUID, name, displayName string, creds map[string]string) error {
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	// Encrypt using AES-GCM
	encrypted, err := crypto.Encrypt(string(credsJSON), s.encryptionKey)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}

	// Standard fields
	err = s.client.IntegrationConfig.Create().
		SetName(name).
		SetDisplayName(displayName).
		SetEncryptedCredentials(encrypted).
		SetIsActive(true).
		SetStatus("active").
		SetNillableTenantID(tenantID).
		OnConflict(sql.ConflictColumns(integrationconfig.FieldTenantID, integrationconfig.FieldName)).
		UpdateNewValues().
		Exec(ctx)

	if err != nil {
		return fmt.Errorf("save integration config: %w", err)
	}

	// Invalidate Cache
	s.redis.Del(ctx, s.getCacheKey(tenantID, name))

	return nil
}

// ListActiveIntegrations returns a list of active integrations (platform-wide + tenant-specific).
func (s *Service) ListActiveIntegrations(ctx context.Context, tenantID *uuid.UUID) ([]*ent.IntegrationConfig, error) {
	query := s.client.IntegrationConfig.Query().Where(integrationconfig.IsActive(true))
	
	if tenantID != nil {
		query = query.Where(
			integrationconfig.Or(
				integrationconfig.TenantIDIsNil(),
				integrationconfig.TenantIDEQ(*tenantID),
			),
		)
	} else {
		query = query.Where(integrationconfig.TenantIDIsNil())
	}

	return query.All(ctx)
}

// ListAll returns all integrations for a tenant or platform.
func (s *Service) ListAll(ctx context.Context, tenantID *uuid.UUID) ([]*ent.IntegrationConfig, error) {
	query := s.client.IntegrationConfig.Query()
	if tenantID != nil {
		query = query.Where(integrationconfig.TenantIDEQ(*tenantID))
	} else {
		query = query.Where(integrationconfig.TenantIDIsNil())
	}
	return query.All(ctx)
}

// GetByID retrieves an integration by ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*ent.IntegrationConfig, error) {
	return s.client.IntegrationConfig.Get(ctx, id)
}

// Delete removes an integration and invalidates cache.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	config, err := s.client.IntegrationConfig.Get(ctx, id)
	if err != nil {
		return err
	}

	if err := s.client.IntegrationConfig.DeleteOneID(id).Exec(ctx); err != nil {
		return err
	}

	s.redis.Del(ctx, s.getCacheKey(config.TenantID, config.Name))
	return nil
}

// UpdateStatus changes the activation status of an integration.
func (s *Service) UpdateStatus(ctx context.Context, id uuid.UUID, isActive bool) error {
	config, err := s.client.IntegrationConfig.Get(ctx, id)
	if err != nil {
		return err
	}

	status := "active"
	if !isActive {
		status = "inactive"
	}

	err = s.client.IntegrationConfig.UpdateOneID(id).
		SetIsActive(isActive).
		SetStatus(status).
		Exec(ctx)
	if err != nil {
		return err
	}

	// Invalidate cache
	s.redis.Del(ctx, s.getCacheKey(config.TenantID, config.Name))
	return nil
}

func (s *Service) getCacheKey(tenantID *uuid.UUID, name string) string {
	if tenantID == nil {
		return fmt.Sprintf("auth:integration:platform:%s", name)
	}
	return fmt.Sprintf("auth:integration:%s:%s", tenantID.String(), name)
}
