// Package providers defines the email provider interface
package providers

import (
	"context"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Provider defines the interface that all email providers must implement
type Provider interface {
	// Send sends an email message
	Send(ctx context.Context, msg *types.Message) error

	// IsAvailable checks if the provider is available
	IsAvailable() bool

	// Name returns the provider name
	Name() string

	// HealthCheck performs a health check on the provider
	HealthCheck(ctx context.Context) error

	// Close closes the provider connection
	Close() error
}
