package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadReadsCanonicalDatabaseURL(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "development")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable", cfg.DBURL)
}

func TestLoadRejectsProductionWildcardOrigins(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "*")

	_, err := Load()
	require.Error(t, err)
}

func TestLoadRejectsMissingDBURL(t *testing.T) {
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "development")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DB_URL is required")
}

func TestLoadRejectsMissingJWTSecret(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("ENVIRONMENT", "development")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_SECRET is required")
}

func TestLoadRejectsShortJWTSecret(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", "short")
	t.Setenv("ENVIRONMENT", "development")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT_SECRET must be at least 32 characters")
}

func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "invalid")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ENVIRONMENT must be one of")
}

func TestLoadRejectsProductionDBWithoutSSL(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "https://example.com")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sslmode=require")
}

func TestLoadRejectsProductionSMTPWithoutHost(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=require")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "https://example.com")
	t.Setenv("EMAIL_PROVIDER", "smtp")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SMTP_HOST is required")
}

func TestLoadAllowsOptionalNatsEmpty(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("NATS_URL", "")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "nats://localhost:4222", cfg.NatsURL)
}

func TestGetBcryptCostReturnsReducedValueWithoutMutation(t *testing.T) {
	cfg := &Config{
		Environment: "development",
		BcryptCost:  12,
	}
	assert.Equal(t, 4, cfg.GetBcryptCost())
	assert.Equal(t, 12, cfg.BcryptCost)
}

func TestGetEnvAsDurationSupportsAdditionalUnits(t *testing.T) {
	t.Setenv("CACHE_TTL", "5")
	assert.Equal(t, 5*time.Minute, getEnvAsDuration("CACHE_TTL", time.Minute))

	t.Setenv("CACHE_MINUTES", "5")
	assert.Equal(t, 5*time.Minute, getEnvAsDuration("CACHE_MINUTES", time.Minute))

	t.Setenv("CACHE_SECONDS", "2")
	assert.Equal(t, 2*time.Second, getEnvAsDuration("CACHE_SECONDS", time.Minute))

	t.Setenv("CACHE_DAYS", "2")
	assert.Equal(t, 48*time.Hour, getEnvAsDuration("CACHE_DAYS", time.Minute))

	t.Setenv("CACHE_WEEKS", "1")
	assert.Equal(t, 7*24*time.Hour, getEnvAsDuration("CACHE_WEEKS", time.Minute))

	t.Setenv("JWT_EXPIRY", "3")
	assert.Equal(t, 3*time.Second, getEnvAsDuration("JWT_EXPIRY", time.Minute))
}
