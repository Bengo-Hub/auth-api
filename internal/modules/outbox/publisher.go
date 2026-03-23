package outbox

import (
	"context"
	"sync"
	"time"

	events "github.com/Bengo-Hub/shared-events"
	"go.uber.org/zap"
)

// EventPublisher is the interface for publishing events to a message broker.
// Auth-api uses plain NATS (not JetStream) so this adapter is needed.
type EventPublisher interface {
	Publish(ctx context.Context, event *events.Event) error
}

// Publisher polls the outbox and publishes events via plain NATS.
// This is auth-specific because auth-api publishes via conn.Publish (not JetStream)
// for backward compatibility with consumers using nc.Subscribe.
type Publisher struct {
	repo       events.OutboxRepository
	publisher  EventPublisher
	logger     *zap.Logger
	batchSize  int
	pollPeriod time.Duration

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// PublisherConfig holds publisher configuration.
type PublisherConfig struct {
	BatchSize  int
	PollPeriod time.Duration
}

// NewPublisher creates a new outbox publisher.
func NewPublisher(repo events.OutboxRepository, publisher EventPublisher, logger *zap.Logger, cfg PublisherConfig) *Publisher {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.PollPeriod <= 0 {
		cfg.PollPeriod = 5 * time.Second
	}
	return &Publisher{
		repo:       repo,
		publisher:  publisher,
		logger:     logger.Named("outbox.publisher"),
		batchSize:  cfg.BatchSize,
		pollPeriod: cfg.PollPeriod,
		stopCh:     make(chan struct{}),
	}
}

// Start begins the background polling loop.
func (p *Publisher) Start(ctx context.Context) {
	p.wg.Add(1)
	go p.run(ctx)
	p.logger.Info("outbox publisher started",
		zap.Int("batch_size", p.batchSize),
		zap.Duration("poll_period", p.pollPeriod),
	)
}

// Stop gracefully stops the publisher.
func (p *Publisher) Stop() {
	close(p.stopCh)
	p.wg.Wait()
	p.logger.Info("outbox publisher stopped")
}

func (p *Publisher) run(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.pollPeriod)
	defer ticker.Stop()

	p.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

func (p *Publisher) poll(ctx context.Context) {
	records, err := p.repo.GetPendingRecords(ctx, p.batchSize)
	if err != nil {
		p.logger.Error("failed to get pending records", zap.Error(err))
		return
	}

	if len(records) == 0 {
		return
	}

	for _, record := range records {
		event, err := events.FromJSON(record.Payload)
		if err != nil {
			p.logger.Warn("invalid outbox payload, marking failed",
				zap.String("id", record.ID.String()), zap.Error(err))
			_ = p.repo.MarkAsFailed(ctx, record.ID, err.Error(), time.Now())
			continue
		}

		if err := p.publisher.Publish(ctx, event); err != nil {
			p.logger.Warn("failed to publish record",
				zap.String("id", record.ID.String()),
				zap.String("event_type", record.EventType),
				zap.Error(err),
			)
			_ = p.repo.MarkAsFailed(ctx, record.ID, err.Error(), time.Now())
			continue
		}

		if err := p.repo.MarkAsPublished(ctx, record.ID, time.Now()); err != nil {
			p.logger.Error("failed to mark record as published",
				zap.String("id", record.ID.String()), zap.Error(err))
		}
	}
}
