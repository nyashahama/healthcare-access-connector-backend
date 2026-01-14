// Package email provides email service implementation
package email

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/metrics"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/retry"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/templates"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// emailService implements the Service interface
type emailService struct {
	provider       providers.Provider
	templates      *templates.Manager
	config         *types.Config
	logger         *zerolog.Logger
	metrics        *metrics.Collector
	retryStrategy  *retry.Strategy
	circuitBreaker *retry.CircuitBreaker

	// Async email queue
	queue      chan *queuedEmail
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	queueMutex sync.RWMutex
}

// queuedEmail represents an email in the queue
type queuedEmail struct {
	msg      *types.Message
	callback func(error)
}

// NewEmailService creates a new email service
func NewEmailService(cfg *types.Config, frontendUrl string, logger *zerolog.Logger) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create provider based on config
	var provider providers.Provider
	var err error

	switch cfg.Provider {
	case "ses":
		provider, err = createSESProvider(cfg, logger)
	case "smtp":
		provider, err = createSMTPProvider(cfg, logger)
	case "resend":
		provider, err = createResendProvider(cfg, logger)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	// Create templates manager
	templateMgr, err := templates.NewManager(cfg, frontendUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to create template manager: %w", err)
	}

	// Create context for service lifecycle
	ctx, cancel := context.WithCancel(context.Background())

	service := &emailService{
		provider:       provider,
		templates:      templateMgr,
		config:         cfg,
		logger:         logger,
		metrics:        metrics.NewCollector(),
		retryStrategy:  createRetryStrategy(cfg, logger),
		circuitBreaker: createCircuitBreaker(cfg, logger),
		queue:          make(chan *queuedEmail, cfg.QueueSize),
		ctx:            ctx,
		cancel:         cancel,
	}

	// Start worker pool if async is enabled
	if cfg.EnableAsync {
		service.startWorkers()
	}

	logger.Info().
		Str("provider", cfg.Provider).
		Bool("async", cfg.EnableAsync).
		Int("workers", cfg.WorkerPoolSize).
		Msg("Email service initialized")

	return service, nil
}

// Send sends an email asynchronously
func (s *emailService) Send(ctx context.Context, msg *types.Message, callback func(error)) error {
	if !s.config.EnableAsync {
		// Send synchronously if async is disabled
		err := s.SendSync(ctx, msg)
		if callback != nil {
			callback(err)
		}
		return err
	}

	// Queue the email
	s.metrics.RecordQueued()

	select {
	case s.queue <- &queuedEmail{msg: msg, callback: callback}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return types.ErrQueueFull
	}
}

// SendSync sends an email synchronously
func (s *emailService) SendSync(ctx context.Context, msg *types.Message) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	start := time.Now()

	// Use circuit breaker if enabled
	operation := func() error {
		return s.provider.Send(ctx, msg)
	}

	var err error
	if s.config.EnableCircuitBreaker {
		err = s.circuitBreaker.Execute(ctx, operation)
	} else {
		err = operation()
	}

	// Retry on failure
	if err != nil && retry.IsRetryable(err) {
		s.metrics.RecordRetried()
		err = s.retryStrategy.Do(ctx, operation)
	}

	duration := time.Since(start)

	// Record metrics
	if err != nil {
		s.metrics.RecordFailed(s.provider.Name())
		s.logger.Error().
			Err(err).
			Str("provider", s.provider.Name()).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Dur("duration", duration).
			Msg("Failed to send email")
		return err
	}

	s.metrics.RecordSent(s.provider.Name(), duration)
	s.logger.Info().
		Str("provider", s.provider.Name()).
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Dur("duration", duration).
		Msg("Email sent successfully")

	return nil
}

// startWorkers starts the worker pool
func (s *emailService) startWorkers() {
	for i := 0; i < s.config.WorkerPoolSize; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}
}

// worker processes emails from the queue
func (s *emailService) worker(id int) {
	defer s.wg.Done()

	s.logger.Debug().Int("worker_id", id).Msg("Email worker started")

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Debug().Int("worker_id", id).Msg("Email worker stopped")
			return

		case email := <-s.queue:
			ctx, cancel := context.WithTimeout(s.ctx, s.config.SendTimeout)
			err := s.SendSync(ctx, email.msg)
			cancel()

			if email.callback != nil {
				email.callback(err)
			}
		}
	}
}

// Template methods

// SendWelcomeEmail sends a welcome email
func (s *emailService) SendWelcomeEmail(ctx context.Context, to, username string) error {
	subject, text, html := s.templates.RenderWelcome(username)

	return s.SendSync(ctx, &types.Message{
		To:       []string{to},
		Subject:  subject,
		Body:     text,
		HTMLBody: html,
		Template: types.TemplateWelcome,
		ReplyTo:  s.config.GetReplyTo(types.TemplateWelcome),
	})
}

// SendOTPEmail sends an OTP email
func (s *emailService) SendOTPEmail(ctx context.Context, email, otp, userID string) error {
	subject, text, html := s.templates.RenderOTP(email, otp, "")

	return s.SendSync(ctx, &types.Message{
		To:       []string{email},
		Subject:  subject,
		Body:     text,
		HTMLBody: html,
		Template: types.TemplateOTP,
		ReplyTo:  s.config.GetReplyTo(types.TemplateOTP),
	})
}

// SendPasswordResetEmail sends a password reset email
func (s *emailService) SendPasswordResetEmail(ctx context.Context, to, resetToken string) error {
	subject, text, html := s.templates.RenderPasswordReset(resetToken)

	return s.SendSync(ctx, &types.Message{
		To:       []string{to},
		Subject:  subject,
		Body:     text,
		HTMLBody: html,
		Template: types.TemplatePasswordReset,
		ReplyTo:  s.config.GetReplyTo(types.TemplatePasswordReset),
	})
}

// SendVerificationEmail sends a verification email
func (s *emailService) SendVerificationEmail(ctx context.Context, to, verificationToken string) error {
	subject, text, html := s.templates.RenderVerification(verificationToken)

	return s.SendSync(ctx, &types.Message{
		To:       []string{to},
		Subject:  subject,
		Body:     text,
		HTMLBody: html,
		Template: types.TemplateVerification,
		ReplyTo:  s.config.GetReplyTo(types.TemplateVerification),
	})
}

// SendPasswordChangedEmail sends a password changed notification
func (s *emailService) SendPasswordChangedEmail(ctx context.Context, to, username string) error {
	subject, text, html := s.templates.RenderPasswordChanged(username)

	return s.SendSync(ctx, &types.Message{
		To:       []string{to},
		Subject:  subject,
		Body:     text,
		HTMLBody: html,
		Template: types.TemplatePasswordChanged,
		ReplyTo:  s.config.GetReplyTo(types.TemplatePasswordChanged),
	})
}

// SendLoginAlertEmail sends a login alert
func (s *emailService) SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error {
	subject, text, html := s.templates.RenderLoginAlert(username, ipAddress, location)

	return s.SendSync(ctx, &types.Message{
		To:       []string{to},
		Subject:  subject,
		Body:     text,
		HTMLBody: html,
		Template: types.TemplateLoginAlert,
		ReplyTo:  s.config.GetReplyTo(types.TemplateLoginAlert),
	})
}

// HealthCheck performs a health check
func (s *emailService) HealthCheck(ctx context.Context) error {
	return s.provider.HealthCheck(ctx)
}

// GetStats returns service statistics
func (s *emailService) GetStats() map[string]interface{} {
	stats := s.metrics.GetStats()
	stats["queue_size"] = len(s.queue)
	stats["queue_capacity"] = s.config.QueueSize
	return stats
}

// GetHealthStatus returns health status
func (s *emailService) GetHealthStatus() map[string]interface{} {
	return map[string]interface{}{
		"provider_available": s.provider.IsAvailable(),
		"provider_name":      s.provider.Name(),
		"circuit_breaker":    s.circuitBreaker.GetStats(),
		"queue_size":         len(s.queue),
		"queue_capacity":     s.config.QueueSize,
	}
}

func (s *emailService) IsAvailable() bool {
	// Check if provider is available
	if s.provider == nil {
		return false
	}
	return s.provider.IsAvailable()
}

// Close closes the email service
func (s *emailService) Close() error {
	s.logger.Info().Msg("Shutting down email service")

	// Cancel context to stop workers
	s.cancel()

	// Wait for workers to finish
	s.wg.Wait()

	// Close provider
	if err := s.provider.Close(); err != nil {
		s.logger.Error().Err(err).Msg("Failed to close provider")
		return err
	}

	s.logger.Info().Msg("Email service stopped")
	return nil
}

// Helper functions

func createRetryStrategy(cfg *types.Config, logger *zerolog.Logger) *retry.Strategy {
	return &retry.Strategy{
		MaxRetries:   cfg.MaxRetries,
		InitialDelay: cfg.RetryDelay,
		MaxDelay:     cfg.RetryMaxDelay,
		Multiplier:   cfg.RetryMultiplier,
		Logger:       logger,
	}
}

func createCircuitBreaker(cfg *types.Config, logger *zerolog.Logger) *retry.CircuitBreaker {
	return retry.NewCircuitBreaker(
		cfg.CircuitBreakerThreshold,
		cfg.CircuitBreakerTimeout,
		cfg.CircuitBreakerMaxRequests,
		logger,
	)
}
