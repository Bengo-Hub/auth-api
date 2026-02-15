package outbox

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	events "github.com/Bengo-Hub/shared-events"
	"github.com/bengobox/auth-api/internal/ent"
	"github.com/bengobox/auth-api/internal/ent/outboxevent"
	"github.com/google/uuid"
)

// EntRepository implements outbox storage using the Ent ORM.
type EntRepository struct {
	client *ent.Client
	db     *sql.DB
}

// NewEntRepository creates a new outbox repository.
func NewEntRepository(client *ent.Client, db *sql.DB) *EntRepository {
	return &EntRepository{
		client: client,
		db:     db,
	}
}

// CreateOutboxRecord stores an event in the outbox within a SQL transaction.
func (r *EntRepository) CreateOutboxRecord(ctx context.Context, tx *sql.Tx, record *events.OutboxRecord) error {
	query := `
		INSERT INTO outbox_events (id, tenant_id, aggregate_type, aggregate_id, event_type, payload, status, attempts, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := tx.ExecContext(ctx, query,
		record.ID,
		record.TenantID,
		record.AggregateType,
		record.AggregateID,
		record.EventType,
		record.Payload,
		record.Status,
		record.Attempts,
		record.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert outbox record: %w", err)
	}
	return nil
}

// GetPendingRecords fetches pending events for publishing.
func (r *EntRepository) GetPendingRecords(ctx context.Context, limit int) ([]*events.OutboxRecord, error) {
	records, err := r.client.OutboxEvent.Query().
		Where(outboxevent.StatusEQ(outboxevent.StatusPENDING)).
		Order(ent.Asc(outboxevent.FieldCreatedAt)).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("query pending records: %w", err)
	}

	result := make([]*events.OutboxRecord, len(records))
	for i, rec := range records {
		result[i] = &events.OutboxRecord{
			ID:            rec.ID,
			TenantID:      rec.TenantID,
			AggregateType: rec.AggregateType,
			AggregateID:   rec.AggregateID,
			EventType:     rec.EventType,
			Payload:       rec.Payload,
			Status:        string(rec.Status),
			Attempts:      rec.Attempts,
			LastAttemptAt: rec.LastAttemptAt,
			PublishedAt:   rec.PublishedAt,
			ErrorMessage:  rec.ErrorMessage,
			CreatedAt:     rec.CreatedAt,
		}
	}
	return result, nil
}

// MarkAsPublished marks an event as successfully published.
func (r *EntRepository) MarkAsPublished(ctx context.Context, id uuid.UUID, publishedAt time.Time) error {
	return r.client.OutboxEvent.UpdateOneID(id).
		SetStatus(outboxevent.StatusPUBLISHED).
		SetPublishedAt(publishedAt).
		Exec(ctx)
}

// MarkAsFailed marks an event as failed and increments attempts.
func (r *EntRepository) MarkAsFailed(ctx context.Context, id uuid.UUID, errorMessage string, lastAttemptAt time.Time) error {
	rec, err := r.client.OutboxEvent.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("get record: %w", err)
	}

	newAttempts := rec.Attempts + 1
	status := outboxevent.StatusPENDING
	if newAttempts >= 10 {
		status = outboxevent.StatusFAILED
	}

	return r.client.OutboxEvent.UpdateOneID(id).
		SetStatus(status).
		SetAttempts(newAttempts).
		SetLastAttemptAt(lastAttemptAt).
		SetErrorMessage(errorMessage).
		Exec(ctx)
}

// BeginTx starts a database transaction.
func (r *EntRepository) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

// CreateEventWithTx creates an outbox record within an Ent transaction.
func CreateEventWithTx(ctx context.Context, tx *ent.Tx, event *events.Event) error {
	payload, err := event.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	return tx.OutboxEvent.Create().
		SetID(event.ID).
		SetTenantID(event.TenantID).
		SetAggregateType(event.AggregateType).
		SetAggregateID(event.AggregateID).
		SetEventType(event.EventType).
		SetPayload(payload).
		SetStatus(outboxevent.StatusPENDING).
		SetAttempts(0).
		SetCreatedAt(time.Now().UTC()).
		Exec(ctx)
}
