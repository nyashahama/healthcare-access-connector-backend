package smtp

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

func TestProvider_Send(t *testing.T) {
	t.Run("send with unavailable provider", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			config: &emailtypes.Config{
				SMTPHost: "localhost",
				SMTPPort: 1025,
			},
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
			config: &emailtypes.Config{
				SMTPHost: "localhost",
				SMTPPort: 1025,
			},
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
	t.Run("available with host configured", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			config: &emailtypes.Config{
				SMTPHost: "smtp.example.com",
				SMTPPort: 587,
			},
			logger:    &logger,
			available: true,
		}

		assert.True(t, provider.IsAvailable())
	})

	t.Run("not available without host", func(t *testing.T) {
		logger := zerolog.New(nil)
		provider := &Provider{
			config:    nil,
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

	assert.Equal(t, "smtp", provider.Name())
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
		}

		err := provider.Close()
		assert.NoError(t, err)
	})
}

func TestConfig_Validation(t *testing.T) {
	t.Run("valid SMTP config", func(t *testing.T) {
		cfg := &emailtypes.Config{
			Provider:    "smtp",
			SMTPHost:    "smtp.example.com",
			SMTPPort:    587,
			FromAddress: "test@example.com",
			FromName:    "Test",
		}

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing SMTP host", func(t *testing.T) {
		cfg := &emailtypes.Config{
			Provider:    "smtp",
			SMTPHost:    "",
			SMTPPort:    587,
			FromAddress: "test@example.com",
		}

		err := cfg.Validate()
		assert.Error(t, err)
	})
}