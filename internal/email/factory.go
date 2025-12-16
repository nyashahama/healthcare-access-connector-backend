// Package email provides email service factory
package email

import (
	"fmt"

	"github.com/rs/zerolog"
)

// NewEmailService creates an email service based on configuration
func NewEmailService(cfg *Config, logger *zerolog.Logger) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	switch cfg.Provider {
	case "ses":
		return NewSESService(cfg, logger)
	case "smtp":
		return NewSMTPService(cfg, logger)
	default:
		return nil, fmt.Errorf("unsupported email provider: %s", cfg.Provider)
	}
}

// NewFromEnv creates an email service from environment variables
func NewFromEnv(logger *zerolog.Logger) (Service, error) {
	cfg := ConfigFromEnv()
	return NewEmailService(cfg, logger)
}
