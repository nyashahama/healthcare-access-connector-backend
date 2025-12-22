// Package config handles application configuration
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

// Config holds all application configuration
type Config struct {
	// Database
	DBURL string

	// Authentication
	JWTSecret  string
	JWTExpiry  time.Duration
	SMSEnabled bool

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

	// Email Configuration
	EmailFrom     string
	EmailHost     string
	EmailPort     int
	EmailUser     string
	EmailPassword string

	// ===================
	// NEW PERFORMANCE OPTIMIZATIONS
	// ===================

	// Bcrypt Hashing
	BcryptCost int

	// Database Connection Pool
	DBMaxConns        int
	DBMinConns        int
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration

	// Redis Connection Pool
	RedisMaxConns     int
	RedisMinIdleConns int
	RedisPoolTimeout  time.Duration

	// Server Timeouts
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Login Security
	LoginMaxAttempts int
	LoginLockoutMins int

	// Connection Pooling
	HTTPClientTimeout   time.Duration
	HTTPMaxIdleConns    int
	HTTPMaxConnsPerHost int
	HTTPIdleConnTimeout time.Duration

	// Cache Configuration
	CacheEnabled    bool
	CacheDefaultTTL time.Duration
	CacheUserTTL    time.Duration
	CacheSessionTTL time.Duration
	CacheTokenTTL   time.Duration

	// Performance Monitoring
	MetricsEnabled   bool
	MetricsPort      string
	ProfilingEnabled bool
	ProfilingPort    string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Set environment-based defaults
	defaultBcryptCost := 10 // Secure default for production
	if os.Getenv("ENVIRONMENT") == "development" {
		defaultBcryptCost = 4 // Faster for development
	}

	cfg := &Config{
		// Core Configuration
		DBURL:          getEnv("DB_URL", ""),
		JWTSecret:      getEnv("JWT_SECRET", ""),
		Port:           getEnv("PORT", "8080"),
		LogLevel:       getEnv("LOG_LEVEL", "info"),
		Environment:    getEnv("ENVIRONMENT", "development"),
		Timeout:        getEnvAsDuration("TIMEOUT_SECONDS", 30*time.Second),
		RateLimitRPS:   getEnvAsInt("RATE_LIMIT_RPS", 10),
		RateLimitBurst: getEnvAsInt("RATE_LIMIT_BURST", 20),
		JWTExpiry:      getEnvAsDuration("JWT_EXPIRY_HOURS", 24*time.Hour),
		SMSEnabled:     getEnvAsBool("SMS_ENABLED", false),
		RedisURL:       getEnv("REDIS_URL", "redis://localhost:6379"),
		NatsURL:        getEnv("NATS_URL", "nats://localhost:4222"),
		CacheTTL:       getEnvAsDuration("CACHE_TTL_MINUTES", 5*time.Minute),

		// Email Configuration
		EmailFrom:     getEnv("EMAIL_FROM", ""),
		EmailHost:     getEnv("EMAIL_HOST", ""),
		EmailPort:     getEnvAsInt("EMAIL_PORT", 587),
		EmailUser:     getEnv("EMAIL_USER", ""),
		EmailPassword: getEnv("EMAIL_PASSWORD", ""),

		// ===================
		// PERFORMANCE OPTIMIZATIONS
		// ===================

		// Bcrypt Hashing
		BcryptCost: getEnvAsInt("BCRYPT_COST", defaultBcryptCost),

		// Database Connection Pool
		DBMaxConns:        getEnvAsInt("DB_MAX_CONNS", 25),
		DBMinConns:        getEnvAsInt("DB_MIN_CONNS", 5),
		DBMaxConnLifetime: getEnvAsDuration("DB_MAX_CONN_LIFETIME", 1*time.Hour),
		DBMaxConnIdleTime: getEnvAsDuration("DB_MAX_CONN_IDLE_TIME", 5*time.Minute),

		// Redis Connection Pool
		RedisMaxConns:     getEnvAsInt("REDIS_MAX_CONNS", 10),
		RedisMinIdleConns: getEnvAsInt("REDIS_MIN_IDLE_CONNS", 3),
		RedisPoolTimeout:  getEnvAsDuration("REDIS_POOL_TIMEOUT", 1*time.Second),

		// Server Timeouts
		ReadTimeout:  getEnvAsDuration("READ_TIMEOUT", 10*time.Second),
		WriteTimeout: getEnvAsDuration("WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:  getEnvAsDuration("IDLE_TIMEOUT", 60*time.Second),

		// Login Security
		LoginMaxAttempts: getEnvAsInt("LOGIN_MAX_ATTEMPTS", 5),
		LoginLockoutMins: getEnvAsInt("LOGIN_LOCKOUT_MINS", 5),

		// HTTP Connection Pooling
		HTTPClientTimeout:   getEnvAsDuration("HTTP_CLIENT_TIMEOUT", 30*time.Second),
		HTTPMaxIdleConns:    getEnvAsInt("HTTP_MAX_IDLE_CONNS", 100),
		HTTPMaxConnsPerHost: getEnvAsInt("HTTP_MAX_CONNS_PER_HOST", 10),
		HTTPIdleConnTimeout: getEnvAsDuration("HTTP_IDLE_CONN_TIMEOUT", 90*time.Second),

		// Cache Configuration
		CacheEnabled:    getEnvAsBool("CACHE_ENABLED", true),
		CacheDefaultTTL: getEnvAsDuration("CACHE_DEFAULT_TTL", 5*time.Minute),
		CacheUserTTL:    getEnvAsDuration("CACHE_USER_TTL", 10*time.Minute),
		CacheSessionTTL: getEnvAsDuration("CACHE_SESSION_TTL", 1*time.Minute),
		CacheTokenTTL:   getEnvAsDuration("CACHE_TOKEN_TTL", 1*time.Minute),

		// Performance Monitoring
		MetricsEnabled:   getEnvAsBool("METRICS_ENABLED", true),
		MetricsPort:      getEnv("METRICS_PORT", "9090"),
		ProfilingEnabled: getEnvAsBool("PROFILING_ENABLED", false),
		ProfilingPort:    getEnv("PROFILING_PORT", "6060"),
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

	// Core validation
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

	// ===================
	// NEW VALIDATIONS
	// ===================

	// Bcrypt validation
	if c.BcryptCost < bcrypt.MinCost || c.BcryptCost > bcrypt.MaxCost {
		errors = append(errors, fmt.Sprintf("BCRYPT_COST must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost))
	}

	// Database pool validation
	if c.DBMaxConns < 1 {
		errors = append(errors, "DB_MAX_CONNS must be at least 1")
	}
	if c.DBMinConns < 1 {
		errors = append(errors, "DB_MIN_CONNS must be at least 1")
	}
	if c.DBMinConns > c.DBMaxConns {
		errors = append(errors, "DB_MIN_CONNS must be <= DB_MAX_CONNS")
	}
	if c.DBMaxConnLifetime < 1*time.Second {
		errors = append(errors, "DB_MAX_CONN_LIFETIME must be at least 1 second")
	}
	if c.DBMaxConnIdleTime < 1*time.Second {
		errors = append(errors, "DB_MAX_CONN_IDLE_TIME must be at least 1 second")
	}

	// Redis pool validation
	if c.RedisMaxConns < 1 {
		errors = append(errors, "REDIS_MAX_CONNS must be at least 1")
	}
	if c.RedisMinIdleConns < 0 {
		errors = append(errors, "REDIS_MIN_IDLE_CONNS must be >= 0")
	}
	if c.RedisMinIdleConns > c.RedisMaxConns {
		errors = append(errors, "REDIS_MIN_IDLE_CONNS must be <= REDIS_MAX_CONNS")
	}

	// Security validation
	if c.LoginMaxAttempts < 1 {
		errors = append(errors, "LOGIN_MAX_ATTEMPTS must be at least 1")
	}
	if c.LoginLockoutMins < 1 {
		errors = append(errors, "LOGIN_LOCKOUT_MINS must be at least 1 minute")
	}

	// Timeout validation
	if c.ReadTimeout < 1*time.Second {
		errors = append(errors, "READ_TIMEOUT must be at least 1 second")
	}
	if c.WriteTimeout < 1*time.Second {
		errors = append(errors, "WRITE_TIMEOUT must be at least 1 second")
	}
	if c.IdleTimeout < 1*time.Second {
		errors = append(errors, "IDLE_TIMEOUT must be at least 1 second")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// Logger creates a configured logger instance
func (c *Config) Logger() *zerolog.Logger {
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}

	// Add color for different environments
	if c.IsDevelopment() {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
			NoColor:    false,
		}
	} else {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
			NoColor:    true,
		}
	}

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

// IsStaging returns true if running in staging environment
func (c *Config) IsStaging() bool {
	return c.Environment == "staging"
}

// GetBcryptCost returns bcrypt cost with environment-aware defaults
func (c *Config) GetBcryptCost() int {
	if c.IsDevelopment() && c.BcryptCost > 8 {
		// Auto-reduce cost in development for faster testing
		c.logDevelopmentWarning("Using bcrypt cost 4 for development (was %d)", c.BcryptCost)
		return 4
	}
	return c.BcryptCost
}

// GetDatabasePoolConfig returns database pool configuration
func (c *Config) GetDatabasePoolConfig() map[string]interface{} {
	return map[string]interface{}{
		"max_conns":         c.DBMaxConns,
		"min_conns":         c.DBMinConns,
		"max_conn_lifetime": c.DBMaxConnLifetime.String(),
		"max_conn_idle":     c.DBMaxConnIdleTime.String(),
	}
}

// GetRedisPoolConfig returns Redis pool configuration
func (c *Config) GetRedisPoolConfig() map[string]interface{} {
	return map[string]interface{}{
		"max_conns":      c.RedisMaxConns,
		"min_idle_conns": c.RedisMinIdleConns,
		"pool_timeout":   c.RedisPoolTimeout.String(),
	}
}

// logDevelopmentWarning logs a warning only in development
func (c *Config) logDevelopmentWarning(format string, args ...interface{}) {
	if c.IsDevelopment() {
		fmt.Printf("[DEV WARNING] "+format+"\n", args...)
	}
}

// ===================
// Helper Functions
// ===================

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

// getEnvAsBool gets an environment variable as bool or returns default
func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// GetCacheConfig returns cache configuration
func (c *Config) GetCacheConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":     c.CacheEnabled,
		"default_ttl": c.CacheDefaultTTL.String(),
		"user_ttl":    c.CacheUserTTL.String(),
		"session_ttl": c.CacheSessionTTL.String(),
		"token_ttl":   c.CacheTokenTTL.String(),
	}
}

// GetPerformanceConfig returns performance configuration
func (c *Config) GetPerformanceConfig() map[string]interface{} {
	return map[string]interface{}{
		"bcrypt_cost":        c.GetBcryptCost(),
		"login_max_attempts": c.LoginMaxAttempts,
		"login_lockout_mins": c.LoginLockoutMins,
		"metrics_enabled":    c.MetricsEnabled,
		"profiling_enabled":  c.ProfilingEnabled,
	}
}
