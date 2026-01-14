// Package metrics provides Prometheus integration
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusCollector collects metrics for Prometheus
type PrometheusCollector struct {
	emailsSent    *prometheus.CounterVec
	emailsFailed  *prometheus.CounterVec
	emailDuration *prometheus.HistogramVec
	emailsInQueue prometheus.Gauge
	retryAttempts *prometheus.CounterVec
}

// NewPrometheusCollector creates a new Prometheus collector
func NewPrometheusCollector(namespace string) *PrometheusCollector {
	return &PrometheusCollector{
		emailsSent: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "emails_sent_total",
				Help:      "Total number of emails sent",
			},
			[]string{"provider", "template"},
		),
		emailsFailed: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "emails_failed_total",
				Help:      "Total number of failed emails",
			},
			[]string{"provider", "template", "error"},
		),
		emailDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "email_send_duration_seconds",
				Help:      "Time taken to send emails",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"provider", "template"},
		),
		emailsInQueue: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "emails_in_queue",
				Help:      "Number of emails currently in queue",
			},
		),
		retryAttempts: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "email_retry_attempts_total",
				Help:      "Total number of retry attempts",
			},
			[]string{"provider"},
		),
	}
}

// RecordSent records a successful email send
func (p *PrometheusCollector) RecordSent(provider, template string, duration time.Duration) {
	p.emailsSent.WithLabelValues(provider, template).Inc()
	p.emailDuration.WithLabelValues(provider, template).Observe(duration.Seconds())
}

// RecordFailed records a failed email send
func (p *PrometheusCollector) RecordFailed(provider, template, errorType string) {
	p.emailsFailed.WithLabelValues(provider, template, errorType).Inc()
}

// SetQueueSize sets the current queue size
func (p *PrometheusCollector) SetQueueSize(size int) {
	p.emailsInQueue.Set(float64(size))
}

// RecordRetry records a retry attempt
func (p *PrometheusCollector) RecordRetry(provider string) {
	p.retryAttempts.WithLabelValues(provider).Inc()
}
