package middleware

import (
	"context"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// MetricsMiddleware implements metrics collection middleware
type MetricsMiddleware struct {
	metrics MetricsCollector
}

// MetricsCollector defines the interface for metrics collection
type MetricsCollector interface {
	RecordSent(provider string, duration time.Duration)
	RecordFailed(provider, template string, err error)
	RecordQueued()
	RecordRetried()
	RecordQueueWait(duration time.Duration)
	RecordCircuitState(state string)
	RecordCircuitResult(success bool)
	RecordRateLimitHit()
	RecordRateLimitDrop()
	UpdateQueueSize(size, capacity int)
	UpdateProviderQuota(provider string, used, limit int64)
	GetStats() map[string]interface{}
}

// NewMetricsMiddleware creates a new metrics middleware
func NewMetricsMiddleware(collector MetricsCollector) *MetricsMiddleware {
	return &MetricsMiddleware{
		metrics: collector,
	}
}

// Wrap wraps the next handler with metrics collection
func (m *MetricsMiddleware) Wrap(next Handler) Handler {
	return HandlerFunc(func(ctx context.Context, msg *types.Message) error {
		start := time.Now()
		
		// Execute the handler
		err := next.Handle(ctx, msg)
		
		duration := time.Since(start)
		
		// Record metrics
		if err != nil {
			m.metrics.RecordFailed("unknown", string(msg.Template), err)
		} else {
			m.metrics.RecordSent("unknown", duration)
		}
		
		return err
	})
}

// GetStats returns metrics statistics
func (m *MetricsMiddleware) GetStats() map[string]interface{} {
	return m.metrics.GetStats()
}