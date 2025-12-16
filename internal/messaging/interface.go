// Package messaging provides message broker abstraction
package messaging

import "errors"

// ErrBrokerUnavailable indicates the message broker is unavailable
var ErrBrokerUnavailable = errors.New("message broker unavailable")

// Broker defines the message broker interface
type Broker interface {
	// Publish publishes a message to a subject
	Publish(subject string, data []byte) error

	// PublishJSON publishes a JSON-encoded message to a subject
	PublishJSON(subject string, data interface{}) error

	// Subscribe subscribes to a subject with a handler
	Subscribe(subject string, handler func([]byte) error) error

	// Close closes the broker connection
	Close() error

	// IsAvailable checks if the broker is available
	IsAvailable() bool
}
