package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadReadsCanonicalDatabaseURL(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "development")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable", cfg.DBURL)
}

func TestLoadRejectsProductionWildcardOrigins(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "*")

	_, err := Load()
	require.Error(t, err)
}
