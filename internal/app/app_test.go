package app

import (
	"math"
	"testing"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/stretchr/testify/require"
)

func TestNewPoolConfigAppliesConfiguredLimits(t *testing.T) {
	cfg := &config.Config{
		DBMaxConns:        11,
		DBMinConns:        3,
		DBMaxConnLifetime: time.Hour,
		DBMaxConnIdleTime: 5 * time.Minute,
	}

	poolCfg, err := newPoolConfig("postgresql://postgres:replace_me@localhost:5432/app_db?sslmode=disable", cfg)
	require.NoError(t, err)
	require.Equal(t, int32(11), poolCfg.MaxConns)
	require.Equal(t, int32(3), poolCfg.MinConns)
	require.Equal(t, time.Hour, poolCfg.MaxConnLifetime)
	require.Equal(t, 5*time.Minute, poolCfg.MaxConnIdleTime)
}

func TestNewPoolConfigRejectsOversizedConnectionLimits(t *testing.T) {
	cfg := &config.Config{
		DBMaxConns:        math.MaxInt32 + 1,
		DBMinConns:        1,
		DBMaxConnLifetime: time.Hour,
		DBMaxConnIdleTime: 5 * time.Minute,
	}

	_, err := newPoolConfig("postgresql://postgres:replace_me@localhost:5432/app_db?sslmode=disable", cfg)
	require.ErrorContains(t, err, "DB_MAX_CONNS must be between 0 and")
}
