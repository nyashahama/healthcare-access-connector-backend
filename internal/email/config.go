// Package email configuration from environment
package email

import (
	"os"
	"strconv"
)

// ConfigFromEnv loads email configuration from environment variables
func ConfigFromEnv() *Config {
	cfg := &Config{
		Provider:    getEnv("EMAIL_PROVIDER", "ses"),
		FromAddress: getEnv("EMAIL_FROM_ADDRESS", "noreply@yourdomain.com"),
		FromName:    getEnv("EMAIL_FROM_NAME", "Your App"),

		// AWS SES
		AWSRegion:          getEnv("AWS_REGION", "us-east-1"),
		AWSAccessKeyID:     getEnv("AWS_ACCESS_KEY_ID", ""),
		AWSSecretAccessKey: getEnv("AWS_SECRET_ACCESS_KEY", ""),

		// SMTP (for local dev with Mailpit)
		SMTPHost:     getEnv("SMTP_HOST", "localhost"),
		SMTPPort:     getEnvAsInt("SMTP_PORT", 1025),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPUseTLS:   getEnvAsBool("SMTP_USE_TLS", false),
	}

	return cfg
}

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
