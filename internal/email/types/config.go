// Package types defines core email types
package types

import (
	"fmt"
	"time"
)

// Config holds email service configuration
type Config struct {
	// Provider settings
	Provider    string // "ses", "smtp", or "resend"
	FromAddress string
	FromName    string

	// AWS SES config
	AWSRegion          string
	AWSAccessKeyID     string
	AWSSecretAccessKey string

	// SMTP config
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPUseTLS   bool

	// Resend config
	ResendAPIKey string

	// Retry configuration
	MaxRetries     int
	RetryDelay     time.Duration
	RetryMaxDelay  time.Duration
	RetryMultiplier float64

	// Circuit breaker configuration
	CircuitBreakerThreshold   int
	CircuitBreakerTimeout     time.Duration
	CircuitBreakerMaxRequests int

	// Performance settings
	WorkerPoolSize int
	QueueSize      int
	SendTimeout    time.Duration

	// Feature flags
	EnableMetrics       bool
	EnableCircuitBreaker bool
	EnableAsync         bool
}

// Validate validates email configuration
func (c *Config) Validate() error {
	if c.FromAddress == "" {
		return fmt.Errorf("from address is required")
	}

	if c.Provider == "" {
		c.Provider = "ses" // Default to SES
	}

	switch c.Provider {
	case "ses":
		if c.AWSRegion == "" {
			return fmt.Errorf("AWS region is required for SES")
		}
	case "smtp":
		if c.SMTPHost == "" {
			return fmt.Errorf("SMTP host is required")
		}
		if c.SMTPPort == 0 {
			c.SMTPPort = 587
		}
	case "resend":
		if c.ResendAPIKey == "" {
			return fmt.Errorf("Resend API key is required")
		}
	default:
		return fmt.Errorf("invalid email provider: %s (must be 'ses', 'smtp', or 'resend')", c.Provider)
	}

	// Set defaults for retry
	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
	if c.RetryDelay == 0 {
		c.RetryDelay = time.Second
	}
	if c.RetryMaxDelay == 0 {
		c.RetryMaxDelay = 30 * time.Second
	}
	if c.RetryMultiplier == 0 {
		c.RetryMultiplier = 2.0
	}

	// Set defaults for circuit breaker
	if c.CircuitBreakerThreshold == 0 {
		c.CircuitBreakerThreshold = 5
	}
	if c.CircuitBreakerTimeout == 0 {
		c.CircuitBreakerTimeout = 60 * time.Second
	}
	if c.CircuitBreakerMaxRequests == 0 {
		c.CircuitBreakerMaxRequests = 1
	}

	// Set defaults for performance
	if c.WorkerPoolSize == 0 {
		c.WorkerPoolSize = 10
	}
	if c.QueueSize == 0 {
		c.QueueSize = 100
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = 30 * time.Second
	}

	return nil
}