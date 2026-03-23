// Package outbox provides the auth-specific outbox publisher that uses plain NATS
// instead of JetStream. The repository is provided by the shared-events library
// (eventslib.NewSQLOutboxRepository). Only the Publisher is auth-specific because
// auth-api publishes to plain NATS subjects (not JetStream streams) for backward
// compatibility with consumers using nc.Subscribe.
package outbox
