package cache

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/bengobox/auth-service/internal/config"
	"github.com/redis/go-redis/v9"
)

// New initialises a Redis client using the provided configuration.
func New(cfg config.RedisConfig) (*redis.Client, error) {
	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
		// Disable client-side caching to avoid "maint_notifications" error
		// Redis 7.x doesn't support this subcommand, causing harmless warnings
		DisableIndentity: true,
	}

	if cfg.EnableTLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := redis.NewClient(opts)
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return client, nil
}
