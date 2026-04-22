package app

import (
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

	poolCfg, err := newPoolConfig("postgresql://postgres:admin@localhost:5432/app_db?sslmode=disable", cfg)
	require.NoError(t, err)
	require.Equal(t, int32(11), poolCfg.MaxConns)
	require.Equal(t, int32(3), poolCfg.MinConns)
	require.Equal(t, time.Hour, poolCfg.MaxConnLifetime)
	require.Equal(t, 5*time.Minute, poolCfg.MaxConnIdleTime)
}
