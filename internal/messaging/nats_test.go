package messaging

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNatsBroker_Publish(t *testing.T) {
	t.Run("publish when unavailable", func(t *testing.T) {
		broker := &natsBroker{
			logger:    nil,
			available: false,
			conn:      nil,
		}

		err := broker.Publish("test.subject", []byte("test message"))
		assert.Error(t, err)
		assert.Equal(t, ErrBrokerUnavailable, err)
	})
}

func TestNatsBroker_PublishJSON(t *testing.T) {
	t.Run("publish JSON when unavailable", func(t *testing.T) {
		broker := &natsBroker{
			logger:    nil,
			available: false,
			conn:      nil,
		}

		data := map[string]interface{}{
			"key":   "value",
			"count": 42,
		}

		err := broker.PublishJSON("test.subject", data)
		assert.Error(t, err)
		assert.Equal(t, ErrBrokerUnavailable, err)
	})

	t.Run("publish JSON with invalid data", func(t *testing.T) {
		broker := &natsBroker{
			logger:    nil,
			available: false,
			conn:      nil,
		}

		err := broker.PublishJSON("test.subject", make(chan int))
		assert.Error(t, err)
	})
}

func TestNatsBroker_Subscribe(t *testing.T) {
	t.Run("subscribe when unavailable", func(t *testing.T) {
		broker := &natsBroker{
			logger:    nil,
			available: false,
			conn:      nil,
		}

		err := broker.Subscribe("test.subject", func(data []byte) error { return nil })
		assert.Error(t, err)
		assert.Equal(t, ErrBrokerUnavailable, err)
	})
}

func TestNatsBroker_Close(t *testing.T) {
	t.Run("close nil connection", func(t *testing.T) {
		broker := &natsBroker{
			logger:    nil,
			available: false,
			conn:      nil,
		}

		err := broker.Close()
		require.NoError(t, err)
	})
}

func TestNatsBroker_IsAvailable(t *testing.T) {
	t.Run("not available when unavailable", func(t *testing.T) {
		broker := &natsBroker{
			logger:    nil,
			available: false,
			conn:      nil,
		}

		assert.False(t, broker.IsAvailable())
	})
}

func TestNewNATSBroker(t *testing.T) {
	t.Run("creates broker with empty URL", func(t *testing.T) {
		logger := zerolog.New(nil)
		broker, err := NewNATSBroker("", &logger)
		require.NoError(t, err)
		assert.NotNil(t, broker)
		assert.False(t, broker.IsAvailable())
	})
}

func TestBroker_Interface(t *testing.T) {
	t.Run("natsBroker implements Broker interface", func(t *testing.T) {
		var broker Broker = &natsBroker{}
		assert.NotNil(t, broker)
	})
}

func TestErrBrokerUnavailable(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		assert.Equal(t, "message broker unavailable", ErrBrokerUnavailable.Error())
	})
}

func TestMessageSerialization(t *testing.T) {
	t.Run("serializes map to JSON", func(t *testing.T) {
		msg := map[string]interface{}{
			"type":      "notification",
			"timestamp": time.Now().Unix(),
			"data": map[string]interface{}{
				"user_id": "123",
				"action":  "login",
			},
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		var parsed map[string]interface{}
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)
		assert.Equal(t, "notification", parsed["type"])
	})

	t.Run("handles nested structs", func(t *testing.T) {
		msg := struct {
			Type    string                 `json:"type"`
			Payload map[string]interface{} `json:"payload"`
		}{
			Type: "consultation",
			Payload: map[string]interface{}{
				"id":     "abc-123",
				"status": "in_progress",
			},
		}

		data, err := json.Marshal(msg)
		require.NoError(t, err)

		var parsed struct {
			Type    string                 `json:"type"`
			Payload map[string]interface{} `json:"payload"`
		}
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)
		assert.Equal(t, "consultation", parsed.Type)
		assert.Equal(t, "abc-123", parsed.Payload["id"])
	})
}

func TestSubjectNaming(t *testing.T) {
	t.Run("valid subject patterns", func(t *testing.T) {
		validSubjects := []string{
			"notifications",
			"notifications.user.123",
			"events.consultation.created",
			"events.consultation.*",
			"events.>",
		}

		for _, subject := range validSubjects {
			broker := &natsBroker{
				logger:    nil,
				available: false,
				conn:      nil,
			}

			err := broker.Publish(subject, []byte("test"))
			assert.Error(t, err)
		}
	})
}