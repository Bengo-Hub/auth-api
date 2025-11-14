package revocation

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store manages access token revocations backed by Redis.
type Store struct {
	client    *redis.Client
	namespace string
}

// New creates a revocation Store.
func New(client *redis.Client, namespace string) *Store {
	ns := namespace
	if ns == "" {
		ns = "auth"
	}
	return &Store{client: client, namespace: ns}
}

func (s *Store) key(jti string) string {
	return fmt.Sprintf("%s:revoked:jti:%s", s.namespace, jti)
}

// Revoke marks a JTI as revoked for the provided TTL.
func (s *Store) Revoke(ctx context.Context, jti string, ttl time.Duration) error {
	return s.client.Set(ctx, s.key(jti), "1", ttl).Err()
}

// IsRevoked checks if the JTI is revoked.
func (s *Store) IsRevoked(ctx context.Context, jti string) (bool, error) {
	val, err := s.client.Get(ctx, s.key(jti)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return val == "1", nil
}
