// Package config handles application configuration
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Config holds all application configuration
type Config struct {
	// Database
	DBURL string

	// Authentication
	JWTSecret string
	JWTExpiry time.Duration

	// Server
	Port           string
	LogLevel       string
	Timeout        time.Duration
	Environment    string
	AllowedOrigins []string

	// Rate Limiting
	RateLimitRPS   int
	RateLimitBurst int

	// External Services
	RedisURL string
	NatsURL  string
	CacheTTL time.Duration
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		DBURL:          getEnv("DB_URL", ""),
		JWTSecret:      getEnv("JWT_SECRET", ""),
		Port:           getEnv("PORT", "8080"),
		LogLevel:       getEnv("LOG_LEVEL", "info"),
		Environment:    getEnv("ENVIRONMENT", "development"),
		Timeout:        getEnvAsDuration("TIMEOUT_SECONDS", 30*time.Second),
		RateLimitRPS:   getEnvAsInt("RATE_LIMIT_RPS", 10),
		RateLimitBurst: getEnvAsInt("RATE_LIMIT_BURST", 20),
		JWTExpiry:      getEnvAsDuration("JWT_EXPIRY_HOURS", 24*time.Hour),
		RedisURL:       getEnv("REDIS_URL", "redis://localhost:6379"),
		NatsURL:        getEnv("NATS_URL", "nats://localhost:4222"),
		CacheTTL:       getEnvAsDuration("CACHE_TTL_MINUTES", 5*time.Minute),
	}

	// Ensure port has colon prefix
	if !strings.HasPrefix(cfg.Port, ":") {
		cfg.Port = ":" + cfg.Port
	}

	// Parse allowed origins
	originsStr := getEnv("ALLOWED_ORIGINS", "*")
	cfg.AllowedOrigins = parseAllowedOrigins(originsStr)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	var errors []string

	if c.DBURL == "" {
		errors = append(errors, "DB_URL is required")
	}

	if c.JWTSecret == "" {
		errors = append(errors, "JWT_SECRET is required")
	} else if len(c.JWTSecret) < 32 {
		errors = append(errors, "JWT_SECRET must be at least 32 characters long")
	}

	if c.Timeout < time.Second {
		errors = append(errors, "TIMEOUT_SECONDS must be at least 1 second")
	}

	if c.JWTExpiry < time.Minute {
		errors = append(errors, "JWT_EXPIRY_HOURS must be at least 1 minute")
	}

	if c.RateLimitRPS < 1 {
		errors = append(errors, "RATE_LIMIT_RPS must be at least 1")
	}

	if c.RateLimitBurst < c.RateLimitRPS {
		errors = append(errors, "RATE_LIMIT_BURST must be >= RATE_LIMIT_RPS")
	}

	validEnvs := map[string]bool{"development": true, "staging": true, "production": true}
	if !validEnvs[c.Environment] {
		errors = append(errors, "ENVIRONMENT must be one of: development, staging, production")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// Logger creates a configured logger instance
func (c *Config) Logger() *zerolog.Logger {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	logger := zerolog.New(output).With().Timestamp().Logger()

	logLevel, err := zerolog.ParseLevel(c.LogLevel)
	if err != nil {
		logLevel = zerolog.InfoLevel
		logger.Warn().Str("log_level", c.LogLevel).Msg("Invalid log level, defaulting to info")
	}

	zerolog.SetGlobalLevel(logLevel)
	return &logger
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// getEnv gets an environment variable or returns default
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets an environment variable as int or returns default
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}

// getEnvAsDuration gets an environment variable as duration or returns default
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	// Try parsing as integer (seconds/hours depending on key)
	if value, err := strconv.Atoi(valueStr); err == nil {
		if strings.Contains(key, "HOURS") {
			return time.Duration(value) * time.Hour
		} else if strings.Contains(key, "MINUTES") {
			return time.Duration(value) * time.Minute
		}
		return time.Duration(value) * time.Second
	}

	// Try parsing as duration string
	if duration, err := time.ParseDuration(valueStr); err == nil {
		return duration
	}

	return defaultValue
}

// parseAllowedOrigins parses comma-separated origins
func parseAllowedOrigins(originsStr string) []string {
	origins := strings.Split(originsStr, ",")
	result := make([]string, 0, len(origins))
	for _, origin := range origins {
		if trimmed := strings.TrimSpace(origin); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
