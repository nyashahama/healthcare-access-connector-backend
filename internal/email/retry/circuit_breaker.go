// Package retry implements circuit breaker pattern
package retry

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// State represents the circuit breaker state
type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	mu              sync.RWMutex
	state           State
	failureCount    int
	successCount    int
	lastFailureTime time.Time
	threshold       int
	timeout         time.Duration
	maxRequests     int
	logger          *zerolog.Logger
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(threshold int, timeout time.Duration, maxRequests int, logger *zerolog.Logger) *CircuitBreaker {
	return &CircuitBreaker{
		state:       StateClosed,
		threshold:   threshold,
		timeout:     timeout,
		maxRequests: maxRequests,
		logger:      logger,
	}
}

// Execute runs the operation through the circuit breaker
func (cb *CircuitBreaker) Execute(ctx context.Context, operation func() error) error {
	// Check if circuit is open
	if !cb.canExecute() {
		cb.logger.Warn().
			Str("state", cb.getStateName()).
			Msg("Circuit breaker is open, rejecting request")
		return emailtypes.ErrCircuitOpen
	}

	// Execute the operation
	err := operation()

	// Record the result
	cb.recordResult(err)

	return err
}

// canExecute checks if the operation can be executed
func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true

	case StateOpen:
		// Check if timeout has elapsed
		if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.logger.Info().Msg("Circuit breaker transitioning to half-open")
			cb.state = StateHalfOpen
			cb.successCount = 0
			cb.failureCount = 0
			return true
		}
		return false

	case StateHalfOpen:
		// Allow limited requests in half-open state
		return cb.successCount+cb.failureCount < cb.maxRequests

	default:
		return false
	}
}

// recordResult records the result of an operation
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		cb.onSuccess()
	} else {
		cb.onFailure()
	}
}

// onSuccess handles a successful operation
func (cb *CircuitBreaker) onSuccess() {
	switch cb.state {
	case StateClosed:
		cb.failureCount = 0

	case StateHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.maxRequests {
			cb.logger.Info().Msg("Circuit breaker transitioning to closed")
			cb.state = StateClosed
			cb.failureCount = 0
			cb.successCount = 0
		}
	}
}

// onFailure handles a failed operation
func (cb *CircuitBreaker) onFailure() {
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		cb.failureCount++
		if cb.failureCount >= cb.threshold {
			cb.logger.Warn().
				Int("failure_count", cb.failureCount).
				Msg("Circuit breaker transitioning to open")
			cb.state = StateOpen
		}

	case StateHalfOpen:
		cb.logger.Warn().Msg("Circuit breaker transitioning back to open")
		cb.state = StateOpen
		cb.failureCount = 0
		cb.successCount = 0
	}
}

// GetState returns the current state
func (cb *CircuitBreaker) GetState() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// getStateName returns the state name
func (cb *CircuitBreaker) getStateName() string {
	switch cb.state {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Reset resets the circuit breaker
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failureCount = 0
	cb.successCount = 0
	cb.logger.Info().Msg("Circuit breaker reset")
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return map[string]interface{}{
		"state":            cb.getStateName(),
		"failure_count":    cb.failureCount,
		"success_count":    cb.successCount,
		"last_failure_time": cb.lastFailureTime,
		"threshold":        cb.threshold,
		"timeout":          cb.timeout.String(),
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open
var ErrCircuitOpen = errors.New("circuit breaker is open")