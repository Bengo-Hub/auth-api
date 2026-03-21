package middleware

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// RedisSessionResolver resolves opaque session references (UUIDs) to JWT
// tokens stored in Redis. This is used when the bb_session cookie contains
// a session ID instead of the full JWT (admin tokens can exceed the browser
// 4KB cookie limit).
type RedisSessionResolver struct {
	client    *redis.Client
	namespace string
}

// NewRedisSessionResolver creates a resolver that looks up session tokens
// in Redis under the key pattern {namespace}:session_token:{sessionRef}.
func NewRedisSessionResolver(client *redis.Client, namespace string) *RedisSessionResolver {
	return &RedisSessionResolver{client: client, namespace: namespace}
}

// ResolveSessionToken fetches the JWT for the given session reference.
func (r *RedisSessionResolver) ResolveSessionToken(ctx context.Context, sessionRef string) (string, error) {
	key := r.namespace + ":session_token:" + sessionRef
	tok, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("session not found: %w", err)
	}
	return tok, nil
}
