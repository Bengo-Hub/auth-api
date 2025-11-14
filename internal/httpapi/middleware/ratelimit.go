package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter provides a simple fixed-window rate limiter backed by Redis.
type RateLimiter struct {
	client    *redis.Client
	namespace string
}

func NewRateLimiter(client *redis.Client, namespace string) *RateLimiter {
	if namespace == "" {
		namespace = "auth"
	}
	return &RateLimiter{client: client, namespace: namespace}
}

func (l *RateLimiter) key(bucket string, id string, window time.Duration) string {
	return fmt.Sprintf("%s:rl:%s:%s:%d", l.namespace, bucket, id, int(window.Seconds()))
}

// Limit applies a fixed-window limit per identifier function (e.g., IP address).
func (l *RateLimiter) Limit(bucket string, max int, window time.Duration, identify func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if identify == nil {
				next.ServeHTTP(w, r)
				return
			}
			id := identify(r)
			if id == "" || l.client == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := context.Background()
			key := l.key(bucket, id, window)
			// increment and set expiry if new
			count, err := l.client.Incr(ctx, key).Result()
			if err == nil && count == 1 {
				_ = l.client.Expire(ctx, key, window).Err()
			}
			if err != nil || int(count) > max {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
