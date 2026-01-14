// Package metrics provides email service metrics
package metrics

import (
	"sync"
	"time"
)

// Collector collects email service metrics
type Collector struct {
	mu sync.RWMutex

	// Counters
	emailsSent    int64
	emailsFailed  int64
	emailsQueued  int64
	emailsRetried int64

	// Timing
	totalSendTime time.Duration
	minSendTime   time.Duration
	maxSendTime   time.Duration

	// Provider stats
	providerStats map[string]*ProviderStats
}

// ProviderStats tracks statistics for a specific provider
type ProviderStats struct {
	Sent      int64
	Failed    int64
	TotalTime time.Duration
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{
		providerStats: make(map[string]*ProviderStats),
		minSendTime:   time.Hour * 24, // Set high initial value
	}
}

// RecordSent records a successful email send
func (c *Collector) RecordSent(provider string, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.emailsSent++
	c.totalSendTime += duration

	if c.minSendTime > duration {
		c.minSendTime = duration
	}
	if c.maxSendTime < duration {
		c.maxSendTime = duration
	}

	// Update provider stats
	if _, exists := c.providerStats[provider]; !exists {
		c.providerStats[provider] = &ProviderStats{}
	}
	c.providerStats[provider].Sent++
	c.providerStats[provider].TotalTime += duration
}

// RecordFailed records a failed email send
func (c *Collector) RecordFailed(provider string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.emailsFailed++

	// Update provider stats
	if _, exists := c.providerStats[provider]; !exists {
		c.providerStats[provider] = &ProviderStats{}
	}
	c.providerStats[provider].Failed++
}

// RecordQueued records an email being queued
func (c *Collector) RecordQueued() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.emailsQueued++
}

// RecordRetried records a retry attempt
func (c *Collector) RecordRetried() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.emailsRetried++
}

// GetStats returns current statistics
func (c *Collector) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	avgSendTime := time.Duration(0)
	if c.emailsSent > 0 {
		avgSendTime = c.totalSendTime / time.Duration(c.emailsSent)
	}

	stats := map[string]interface{}{
		"emails_sent":     c.emailsSent,
		"emails_failed":   c.emailsFailed,
		"emails_queued":   c.emailsQueued,
		"emails_retried":  c.emailsRetried,
		"avg_send_time":   avgSendTime.String(),
		"min_send_time":   c.minSendTime.String(),
		"max_send_time":   c.maxSendTime.String(),
		"total_send_time": c.totalSendTime.String(),
		"success_rate":    c.calculateSuccessRate(),
	}

	// Add provider stats
	providerStats := make(map[string]interface{})
	for provider, stats := range c.providerStats {
		avgTime := time.Duration(0)
		if stats.Sent > 0 {
			avgTime = stats.TotalTime / time.Duration(stats.Sent)
		}

		providerStats[provider] = map[string]interface{}{
			"sent":          stats.Sent,
			"failed":        stats.Failed,
			"avg_send_time": avgTime.String(),
		}
	}
	stats["providers"] = providerStats

	return stats
}

// calculateSuccessRate calculates the success rate
func (c *Collector) calculateSuccessRate() float64 {
	total := c.emailsSent + c.emailsFailed
	if total == 0 {
		return 0
	}
	return float64(c.emailsSent) / float64(total) * 100
}

// Reset resets all metrics
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.emailsSent = 0
	c.emailsFailed = 0
	c.emailsQueued = 0
	c.emailsRetried = 0
	c.totalSendTime = 0
	c.minSendTime = time.Hour * 24
	c.maxSendTime = 0
	c.providerStats = make(map[string]*ProviderStats)
}
