// Package email provides email configuration
package email

import (
	"os"
	"strconv"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// ConfigFromEnv loads email configuration from environment variables
func ConfigFromEnv() *types.Config {
	cfg := &types.Config{
		Provider:    getEnv("EMAIL_PROVIDER", "resend"),
		FromAddress: getEnv("EMAIL_FROM_ADDRESS", "noreply@hac.com"),
		FromName:    getEnv("EMAIL_FROM_NAME", "Healthcare Access Connector"),

		NoReplyAddress: getEnv("EMAIL_NOREPLY_ADDRESS", ""),
		SupportAddress: getEnv("EMAIL_SUPPORT_ADDRESS", ""),
		HealthAddress:  getEnv("EMAIL_HEALTH_ADDRESS", ""),

		// AWS SES
		AWSRegion:          getEnv("AWS_REGION", "us-east-1"),
		AWSAccessKeyID:     getEnv("AWS_ACCESS_KEY_ID", ""),
		AWSSecretAccessKey: getEnv("AWS_SECRET_ACCESS_KEY", ""),

		// SMTP
		SMTPHost:     getEnv("SMTP_HOST", "localhost"),
		SMTPPort:     getEnvAsInt("SMTP_PORT", 1025),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPUseTLS:   getEnvAsBool("SMTP_USE_TLS", false),

		// Resend
		ResendAPIKey: getEnv("RESEND_API_KEY", ""),

		// Retry configuration
		MaxRetries:      getEnvAsInt("EMAIL_MAX_RETRIES", 3),
		RetryDelay:      getEnvAsDuration("EMAIL_RETRY_DELAY", time.Second),
		RetryMaxDelay:   getEnvAsDuration("EMAIL_RETRY_MAX_DELAY", 30*time.Second),
		RetryMultiplier: getEnvAsFloat("EMAIL_RETRY_MULTIPLIER", 2.0),

		// Circuit breaker
		CircuitBreakerThreshold:   getEnvAsInt("EMAIL_CIRCUIT_BREAKER_THRESHOLD", 5),
		CircuitBreakerTimeout:     getEnvAsDuration("EMAIL_CIRCUIT_BREAKER_TIMEOUT", 60*time.Second),
		CircuitBreakerMaxRequests: getEnvAsInt("EMAIL_CIRCUIT_BREAKER_MAX_REQUESTS", 1),

		// Performance
		WorkerPoolSize: getEnvAsInt("EMAIL_WORKER_POOL_SIZE", 10),
		QueueSize:      getEnvAsInt("EMAIL_QUEUE_SIZE", 100),
		SendTimeout:    getEnvAsDuration("EMAIL_SEND_TIMEOUT", 30*time.Second),

		// Feature flags
		EnableMetrics:        getEnvAsBool("EMAIL_ENABLE_METRICS", true),
		EnableCircuitBreaker: getEnvAsBool("EMAIL_ENABLE_CIRCUIT_BREAKER", true),
		EnableAsync:          getEnvAsBool("EMAIL_ENABLE_ASYNC", true),
	}

	return cfg
}

// Helper functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if value, err := strconv.ParseBool(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	return defaultValue
}

func getEnvAsFloat(key string, defaultValue float64) float64 {
	valueStr := os.Getenv(key)
	if value, err := strconv.ParseFloat(valueStr, 64); err == nil {
		return value
	}
	return defaultValue
}
