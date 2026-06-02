package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	sharedevents "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close() //nolint:errcheck
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func userAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string, message string, details map[string]any) {
	writeJSON(w, status, map[string]any{
		"error":   message,
		"code":    code,
		"details": details,
	})
}

// writeOutboxEvent persists a domain event to the outbox table for async NATS
// publishing. Shared by AdminHandler and UserHandler so welcome/provisioning
// events use a single, consistent envelope.
func writeOutboxEvent(ctx context.Context, entClient *ent.Client, logger *zap.Logger, tenantID uuid.UUID, aggregateType string, aggregateID uuid.UUID, eventType string, data map[string]any) {
	event := sharedevents.Event{
		ID:            uuid.New(),
		TenantID:      tenantID,
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		EventType:     eventType,
		Payload:       data,
		Timestamp:     time.Now().UTC(),
		Version:       "1.0",
	}
	payload, err := json.Marshal(event)
	if err != nil {
		if logger != nil {
			logger.Warn("failed to marshal event", zap.Error(err), zap.String("event_type", eventType))
		}
		return
	}
	if err := entClient.OutboxEvent.Create().
		SetTenantID(tenantID).
		SetAggregateType(aggregateType).
		SetAggregateID(aggregateID).
		SetEventType(eventType).
		SetPayload(payload).
		SetStatus(outboxevent.StatusPENDING).
		SetAttempts(0).
		Exec(ctx); err != nil && logger != nil {
		logger.Warn("failed to write outbox event", zap.Error(err), zap.String("event_type", eventType))
	}
}

// invalidateMeCacheKeys deletes any cached /me responses for a user (keyed by
// "<ns>:auth:me:<uid>:<iat>") so a subsequent load reflects profile/password/
// status changes immediately instead of serving the token-lifetime cache.
func invalidateMeCacheKeys(ctx context.Context, rdb *redis.Client, namespace string, userID uuid.UUID) {
	if rdb == nil || namespace == "" {
		return
	}
	pattern := namespace + ":auth:me:" + userID.String() + ":*"
	iter := rdb.Scan(ctx, 0, pattern, 50).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if len(keys) > 0 {
		_ = rdb.Del(ctx, keys...).Err()
	}
}

// generateTempPassword returns a random, reasonably strong temporary password
// suitable for admin-provisioned accounts. The user is forced to change it on
// first interactive (SSO) login via the profile.must_change_password flag.
func generateTempPassword() string {
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnpqrstuvwxyz"
		digits  = "23456789"
		symbols = "!@#$%*?"
	)
	all := upper + lower + digits + symbols
	pick := func(set string) byte {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return set[0]
		}
		return set[n.Int64()]
	}
	// Guarantee at least one of each class, then fill to 16 chars.
	b := []byte{pick(upper), pick(lower), pick(digits), pick(symbols)}
	for len(b) < 16 {
		b = append(b, pick(all))
	}
	// Fisher-Yates shuffle so the guaranteed chars aren't always first.
	for i := len(b) - 1; i > 0; i-- {
		jn, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			continue
		}
		j := int(jn.Int64())
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
