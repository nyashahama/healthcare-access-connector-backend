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
	FromAddress string // Default from address
	FromName    string

	// Multiple from addresses for different purposes
	NoReplyAddress string // For automated emails (no-reply@nyashahama.xyz)
	SupportAddress string // For support emails (support@nyashahama.xyz)
	HealthAddress  string // For health-related emails (health@nyashahama.xyz)

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
	MaxRetries      int
	RetryDelay      time.Duration
	RetryMaxDelay   time.Duration
	RetryMultiplier float64

	// Circuit breaker configuration
	CircuitBreakerThreshold   int
	CircuitBreakerTimeout     time.Duration
	CircuitBreakerMaxRequests int

	// Performance settings
	WorkerPoolSize     int
	QueueSize          int
	SendTimeout        time.Duration
	ConnectionPoolSize int

	// Template configuration
	TemplatesDir  string
	DefaultLocale string

	// Feature flags
	EnableMetrics        bool
	EnableCircuitBreaker bool
	EnableAsync          bool

	// Logging
	LogLevel string
}

// GetFromAddress returns the appropriate from address based on email type
func (c *Config) GetFromAddress(emailType EmailTemplate) string {
	switch emailType {
	case TemplateWelcome, TemplatePasswordReset, TemplateVerification, TemplateOTP, TemplatePasswordChanged, TemplateLoginAlert:
		// Automated system emails use no-reply
		if c.NoReplyAddress != "" {
			return c.NoReplyAddress
		}
	}
	
	// Default to main from address
	return c.FromAddress
}

// GetSupportAddress returns the support email address
func (c *Config) GetSupportAddress() string {
	if c.SupportAddress != "" {
		return c.SupportAddress
	}
	return c.FromAddress
}

// GetHealthAddress returns the health email address
func (c *Config) GetHealthAddress() string {
	if c.HealthAddress != "" {
		return c.HealthAddress
	}
	return c.FromAddress
}

// Validate validates email configuration
func (c *Config) Validate() error {
	if c.FromAddress == "" {
		return fmt.Errorf("from address is required")
	}

	if c.Provider == "" {
		c.Provider = "smtp" // Default to SMTP for local dev
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

	// Set default addresses if not provided
	if c.NoReplyAddress == "" {
		c.NoReplyAddress = c.FromAddress
	}
	if c.SupportAddress == "" {
		c.SupportAddress = c.FromAddress
	}
	if c.HealthAddress == "" {
		c.HealthAddress = c.FromAddress
	}

	// Set defaults for retry
	if c.MaxRetries == 0 {
		c.MaxRetries = 3
	}
	if c.RetryDelay == 0 {
		c.RetryDelay = 2 * time.Second
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
	if c.ConnectionPoolSize == 0 {
		c.ConnectionPoolSize = 5
	}

	// Set defaults for templates
	if c.TemplatesDir == "" {
		c.TemplatesDir = "./internal/email/templates/assets"
	}
	if c.DefaultLocale == "" {
		c.DefaultLocale = "en"
	}

	// Set defaults for logging
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	return nil
}