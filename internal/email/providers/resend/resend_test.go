package resend

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

func TestProvider_Send(t *testing.T) {
	t.Run("send with unavailable provider", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			config:    nil,
			logger:    &logger,
			available: false,
		}

		msg := &emailtypes.Message{
			To:       []string{"test@example.com"},
			Subject:  "Test Subject",
			Body:     "Hello World",
		}

		err := provider.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unavailable")
	})

	t.Run("send with no recipients", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			config:    &emailtypes.Config{},
			logger:    &logger,
			available: true,
		}

		msg := &emailtypes.Message{
			To:       []string{},
			Subject:  "Test Subject",
			Body:     "Hello World",
		}

		err := provider.Send(context.Background(), msg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "recipient")
	})
}

func TestProvider_IsAvailable(t *testing.T) {
	t.Run("available with API key", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			apiKey:    "test-api-key",
			logger:    &logger,
			available: true,
		}

		assert.True(t, provider.IsAvailable())
	})

	t.Run("not available without API key", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			logger:    &logger,
			available: false,
		}

		assert.False(t, provider.IsAvailable())
	})
}

func TestProvider_Name(t *testing.T) {
	logger := zerolog.New(nil)
	provider := &Provider{
		logger: &logger,
	}

	assert.Equal(t, "resend", provider.Name())
}

func TestProvider_HealthCheck(t *testing.T) {
	t.Run("health check when unavailable", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			logger:    &logger,
			available: false,
		}

		err := provider.HealthCheck(context.Background())
		assert.Error(t, err)
	})
}

func TestProvider_Close(t *testing.T) {
	t.Run("close successfully", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			logger: &logger,
			client: &http.Client{Timeout: 30 * time.Second},
		}

		err := provider.Close()
		assert.NoError(t, err)
	})
}

func TestProvider_GetEnvironment(t *testing.T) {
	logger := zerolog.New(nil)
	provider := &Provider{
		logger: &logger,
	}

	env := provider.getEnvironment()
	assert.NotEmpty(t, env)
}

func TestConfig_Validation(t *testing.T) {
	t.Run("valid Resend config", func(t *testing.T) {
		cfg := &emailtypes.Config{
			Provider:    "resend",
			ResendAPIKey: "test-api-key",
			FromAddress: "test@example.com",
			FromName:    "Test",
		}

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing Resend API key", func(t *testing.T) {
		cfg := &emailtypes.Config{
			Provider:    "resend",
			ResendAPIKey: "",
			FromAddress: "test@example.com",
		}

		err := cfg.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "API key")
	})
}