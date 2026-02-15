package events

import (
	"time"

	"github.com/bengobox/auth-api/internal/config"
	"github.com/nats-io/nats.go"
)

// Connect establishes a NATS connection with sane defaults.
func Connect(cfg config.EventsConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("auth-api"),
		nats.Timeout(5 * time.Second),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1),
	}

	return nats.Connect(cfg.NATSURL, opts...)
}
