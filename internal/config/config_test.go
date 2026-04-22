package config

import (
	"strings"
	"testing"

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
