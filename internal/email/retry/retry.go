// Package retry implements retry logic for email sending
package retry

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/rs/zerolog"
)

// Strategy defines retry strategy configuration
type Strategy struct {
	MaxRetries   int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Logger       *zerolog.Logger
}

// DefaultStrategy returns a default retry strategy
func DefaultStrategy(logger *zerolog.Logger) *Strategy {
	return &Strategy{
		MaxRetries:   3,
		InitialDelay: time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Logger:       logger,
	}
}

// Do executes the function with retry logic
func (s *Strategy) Do(ctx context.Context, operation func() error) error {
	var lastErr error

	for attempt := 0; attempt <= s.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try the operation
		err := operation()
		if err == nil {
			if attempt > 0 {
				s.Logger.Info().
					Int("attempt", attempt+1).
					Msg("Operation succeeded after retry")
			}
			return nil
		}

		lastErr = err

		// Don't retry if this was the last attempt
		if attempt == s.MaxRetries {
			break
		}

		// Calculate delay with exponential backoff
		delay := s.calculateDelay(attempt)

		s.Logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Int("max_retries", s.MaxRetries+1).
			Dur("delay", delay).
			Msg("Operation failed, retrying")

		// Wait before retry
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", s.MaxRetries+1, lastErr)
}

// calculateDelay calculates the delay for the next retry using exponential backoff
func (s *Strategy) calculateDelay(attempt int) time.Duration {
	delay := float64(s.InitialDelay) * math.Pow(s.Multiplier, float64(attempt))
	delayDuration := time.Duration(delay)

	if delayDuration > s.MaxDelay {
		return s.MaxDelay
	}

	return delayDuration
}

// IsRetryable determines if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Add logic to determine if errors are retryable
	// For now, we'll retry most errors except context cancellation
	return true
}
