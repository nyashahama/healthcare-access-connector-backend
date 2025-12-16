// Package messaging implements NATS message broker
package messaging

import (
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
)

type natsBroker struct {
	conn      *nats.Conn
	logger    *zerolog.Logger
	available bool
}

// NewNATSBroker creates a new NATS broker
func NewNATSBroker(natsURL string, logger *zerolog.Logger) (Broker, error) {
	broker := &natsBroker{
		logger:    logger,
		available: false,
	}

	if natsURL == "" {
		logger.Info().Msg("NATS URL not provided, broker disabled")
		return broker, nil
	}

	conn, err := nats.Connect(natsURL,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			if err != nil {
				logger.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info().Msg("NATS reconnected")
		}),
	)

	if err != nil {
		logger.Warn().Err(err).Msg("Failed to connect to NATS")
		return broker, err
	}

	broker.conn = conn
	broker.available = true
	logger.Info().Str("url", natsURL).Msg("NATS broker initialized")

	return broker, nil
}

func (b *natsBroker) Publish(subject string, data []byte) error {
	if !b.available {
		return ErrBrokerUnavailable
	}

	if err := b.conn.Publish(subject, data); err != nil {
		b.logger.Error().Err(err).Str("subject", subject).Msg("Failed to publish message")
		return fmt.Errorf("publish to %s: %w", subject, err)
	}

	b.logger.Debug().Str("subject", subject).Int("bytes", len(data)).Msg("Message published")
	return nil
}

func (b *natsBroker) PublishJSON(subject string, data interface{}) error {
	if !b.available {
		return ErrBrokerUnavailable
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	return b.Publish(subject, bytes)
}

func (b *natsBroker) Subscribe(subject string, handler func([]byte) error) error {
	if !b.available {
		return ErrBrokerUnavailable
	}

	_, err := b.conn.Subscribe(subject, func(msg *nats.Msg) {
		if err := handler(msg.Data); err != nil {
			b.logger.Error().
				Err(err).
				Str("subject", subject).
				Msg("Message handler error")
		}
	})

	if err != nil {
		return fmt.Errorf("subscribe to %s: %w", subject, err)
	}

	b.logger.Info().Str("subject", subject).Msg("Subscribed to subject")
	return nil
}

func (b *natsBroker) Close() error {
	if b.conn != nil {
		b.conn.Close()
		b.available = false
		b.logger.Info().Msg("NATS connection closed")
	}
	return nil
}

func (b *natsBroker) IsAvailable() bool {
	return b.available && b.conn != nil && !b.conn.IsClosed()
}