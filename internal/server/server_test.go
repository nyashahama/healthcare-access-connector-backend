package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/stretchr/testify/require"
)

func TestBuildHTTPServerUsesConfiguredTimeouts(t *testing.T) {
	cfg := &config.Config{Port: ":8080", ReadTimeout: 11 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 13 * time.Second}
	srv := &Server{config: cfg}
	httpServer := srv.buildHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	require.Equal(t, 11*time.Second, httpServer.ReadTimeout)
	require.Equal(t, 12*time.Second, httpServer.WriteTimeout)
	require.Equal(t, 13*time.Second, httpServer.IdleTimeout)
}
