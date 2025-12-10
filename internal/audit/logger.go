package audit

import (
	"context"
	"time"

	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/auditlog"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Entry represents a structured audit event.
type Entry struct {
	TenantID   *uuid.UUID
	UserID     *uuid.UUID
	Action     string
	Resource   string
	ResourceID string
	IPAddress  string
	UserAgent  string
	Context    map[string]any
	OccurredAt time.Time
}

// Logger writes audit entries into the database.
type Logger struct {
	client *ent.Client
	logger *zap.Logger
}

// New constructs a Logger.
func New(client *ent.Client, logger *zap.Logger) *Logger {
	return &Logger{client: client, logger: logger}
}

// Record persists an audit entry, logging failures but not interrupting flows.
func (l *Logger) Record(ctx context.Context, entry Entry) {
	if entry.Action == "" {
		return
	}
	builder := l.client.AuditLog.Create().
		SetAction(entry.Action).
		SetResourceType(entry.Resource).
		SetResourceID(entry.ResourceID).
		SetOccurredAt(timeOrDefault(entry.OccurredAt)).
		SetIPAddress(entry.IPAddress).
		SetUserAgent(entry.UserAgent)

	if entry.Context != nil {
		builder.SetContext(entry.Context)
	}
	if entry.TenantID != nil {
		builder.SetTenantID(*entry.TenantID)
	}
	if entry.UserID != nil {
		builder.SetUserID(*entry.UserID)
	}

	if err := builder.Exec(ctx); err != nil {
		l.logger.Warn("failed to persist audit log", zap.Error(err))
	}
}

// ListRecent retrieves most recent entries for debugging/ops.
func (l *Logger) ListRecent(ctx context.Context, limit int) ([]*ent.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	return l.client.AuditLog.
		Query().
		Order(ent.Desc(auditlog.FieldOccurredAt)).
		Limit(limit).
		All(ctx)
}

func timeOrDefault(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}
