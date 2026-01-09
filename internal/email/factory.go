// Package email provides email service factory
package email

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/providers/resend"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/providers/ses"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/providers/smtp"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Service defines the email service interface
type Service interface {
	// Core Methods
	Send(ctx context.Context, msg *types.Message, callback func(error)) error
	SendSync(ctx context.Context, msg *types.Message) error

	// Template Methods
	SendWelcomeEmail(ctx context.Context, to, username string) error
	SendOTPEmail(ctx context.Context, email, otp, userID string) error
	SendPasswordResetEmail(ctx context.Context, to, resetToken string) error
	SendVerificationEmail(ctx context.Context, to, verificationToken string) error
	SendPasswordChangedEmail(ctx context.Context, to, username string) error
	SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error

	// Health & Monitoring
	HealthCheck(ctx context.Context) error
	GetStats() map[string]interface{}
	GetHealthStatus() map[string]interface{}

	IsAvailable() bool

	// Lifecycle
	Close() error
}

// New creates a new email service
func New(cfg *types.Config, frontendUrl string, logger *zerolog.Logger) (Service, error) {
	return NewEmailService(cfg, frontendUrl, logger)
}

// NewFromEnv creates a new email service from environment variables
func NewFromEnv(frontendUrl string, logger *zerolog.Logger) (Service, error) {
	cfg := ConfigFromEnv()
	return New(cfg, frontendUrl, logger)
}

// Provider factory functions

func createSESProvider(cfg *types.Config, logger *zerolog.Logger) (providers.Provider, error) {
	return ses.New(cfg, logger)
}

func createSMTPProvider(cfg *types.Config, logger *zerolog.Logger) (providers.Provider, error) {
	return smtp.New(cfg, logger)
}

func createResendProvider(cfg *types.Config, logger *zerolog.Logger) (providers.Provider, error) {
	return resend.New(cfg, logger)
}

// CreateProvider creates a provider based on the configuration
func CreateProvider(cfg *types.Config, logger *zerolog.Logger) (providers.Provider, error) {
	switch cfg.Provider {
	case "ses":
		return createSESProvider(cfg, logger)
	case "smtp":
		return createSMTPProvider(cfg, logger)
	case "resend":
		return createResendProvider(cfg, logger)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}
}
