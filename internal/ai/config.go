// Package ai provides configuration for the AI client
package ai

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all AI client configuration
type Config struct {
	// APIKey is the HuggingFace bearer token (HF_API_KEY env var)
	APIKey string

	// Model is the model identifier on the HuggingFace router
	// Defaults to "openai/gpt-oss-20b:fastest"
	Model string

	// RequestTimeout is the per-call HTTP timeout
	// Defaults to 30 seconds
	RequestTimeout time.Duration

	// MaxTokens controls response length (informational; some routers ignore it)
	MaxTokens int

	// Enabled allows the feature to be toggled without removing credentials
	Enabled bool
}

// ConfigFromEnv loads AI config from environment variables.
// Expected env vars:
//
//	HF_API_KEY            – required if AI_ENABLED=true
//	AI_MODEL              – optional, defaults to openai/gpt-oss-20b:fastest
//	AI_REQUEST_TIMEOUT    – optional, Go duration string e.g. "30s", defaults to 30s
//	AI_MAX_TOKENS         – optional, int, defaults to 512
//	AI_ENABLED            – optional, bool, defaults to true when HF_API_KEY is set
func ConfigFromEnv() *Config {
	apiKey := os.Getenv("HF_API_KEY")

	// Default enabled to true only when a key is present
	enabledDefault := apiKey != ""
	enabled := getEnvAsBool("AI_ENABLED", enabledDefault)

	return &Config{
		APIKey:         apiKey,
		Model:          getEnv("AI_MODEL", defaultModel),
		RequestTimeout: getEnvAsDuration("AI_REQUEST_TIMEOUT", 30*time.Second),
		MaxTokens:      getEnvAsInt("AI_MAX_TOKENS", 512),
		Enabled:        enabled,
	}
}

// Validate checks the configuration for required fields
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // disabled configs are always valid
	}
	if c.APIKey == "" {
		return errors.New("ai: HF_API_KEY is required when AI_ENABLED=true")
	}
	if c.RequestTimeout < time.Second {
		return fmt.Errorf("ai: AI_REQUEST_TIMEOUT must be at least 1 second, got %s", c.RequestTimeout)
	}
	if c.MaxTokens < 64 {
		return fmt.Errorf("ai: AI_MAX_TOKENS must be at least 64, got %d", c.MaxTokens)
	}
	return nil
}

// helper functions (unexported, local copies to avoid import cycles)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		return v
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return defaultValue
}
