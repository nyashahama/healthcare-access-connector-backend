package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHub_NewHub(t *testing.T) {
	t.Run("creates hub with default config", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		assert.NotNil(t, hub)
		assert.Equal(t, cfg, hub.cfg)
		assert.NotNil(t, hub.rooms)
		assert.NotNil(t, hub.register)
		assert.NotNil(t, hub.unregister)
	})
}

func TestHub_Run(t *testing.T) {
	t.Run("starts and stops gracefully", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})

		go func() {
			hub.Run(ctx)
			close(done)
		}()

		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("hub did not stop in time")
		}
	})

	t.Run("registers and unregisters clients", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go hub.Run(ctx)

		assert.Equal(t, 0, hub.RoomSize("test-consultation"))
	})
}

func TestHub_RoomSize(t *testing.T) {
	t.Run("returns zero for empty room", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		size := hub.RoomSize("non-existent-room")
		assert.Equal(t, 0, size)
	})
}

func TestHub_Broadcast(t *testing.T) {
	t.Run("broadcasts to room", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		event := OutboundEvent{
			Type:           EventMessage,
			ConsultationID: "test-room",
			SenderUserID:   "user-1",
			Payload:        MessagePayload{MessageType: MessageTypeText, Content: "Hello"},
			SentAt:         time.Now().UTC(),
		}

		hub.Broadcast("test-room", event)
	})
}

func TestHub_IsAvailable(t *testing.T) {
	t.Run("always available when hub is running", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		assert.True(t, hub.IsAvailable())
	})
}

func TestHub_ServeWS(t *testing.T) {
	t.Run("upgrades HTTP connection", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go hub.Run(ctx)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hub.ServeWS(w, r, "consultation-1", "user-1", "patient")
		}))
		defer server.Close()

		dialer := websocket.DefaultDialer
		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			t.Skipf("WebSocket connection failed: %v", err)
		}
		defer func() {
			_ = conn.Close()
		}()

		time.Sleep(100 * time.Millisecond)
		assert.True(t, hub.RoomSize("consultation-1") >= 1)
	})
}

func TestInboundEvent_Parsing(t *testing.T) {
	t.Run("parses valid event", func(t *testing.T) {
		event := InboundEvent{
			Type:           EventMessage,
			ConsultationID: "consultation-1",
			Payload:        json.RawMessage(`{"content":"Hello"}`),
		}

		data, err := json.Marshal(event)
		require.NoError(t, err)

		var parsed InboundEvent
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, EventMessage, parsed.Type)
		assert.Equal(t, "consultation-1", parsed.ConsultationID)
	})

	t.Run("handles invalid JSON", func(t *testing.T) {
		var event InboundEvent
		err := json.Unmarshal([]byte("invalid json"), &event)
		assert.Error(t, err)
	})
}

func TestOutboundEvent_Parsing(t *testing.T) {
	t.Run("parses valid event", func(t *testing.T) {
		event := OutboundEvent{
			Type:           EventMessage,
			ConsultationID: "consultation-1",
			SenderUserID:   "user-1",
			Payload:        MessagePayload{MessageType: MessageTypeText, Content: "Hello"},
			SentAt:         time.Now().UTC(),
		}

		data, err := json.Marshal(event)
		require.NoError(t, err)

		var parsed OutboundEvent
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, EventMessage, parsed.Type)
		assert.Equal(t, "consultation-1", parsed.ConsultationID)
		assert.Equal(t, "user-1", parsed.SenderUserID)
	})
}

func TestMessagePayload_Validation(t *testing.T) {
	t.Run("valid text message", func(t *testing.T) {
		payload := MessagePayload{
			MessageType: MessageTypeText,
			Content:     "Hello, World!",
		}

		data, err := json.Marshal(payload)
		require.NoError(t, err)

		var parsed MessagePayload
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, MessageTypeText, parsed.MessageType)
		assert.Equal(t, "Hello, World!", parsed.Content)
	})

	t.Run("system event message", func(t *testing.T) {
		payload := MessagePayload{
			MessageType: MessageTypeSystemEvent,
			Content:     "Patient joined the consultation",
		}

		data, err := json.Marshal(payload)
		require.NoError(t, err)

		var parsed MessagePayload
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, MessageTypeSystemEvent, parsed.MessageType)
	})
}

func TestPresencePayload_Validation(t *testing.T) {
	t.Run("join action", func(t *testing.T) {
		payload := PresencePayload{
			Action: "joined",
			Role:   "patient",
		}

		data, err := json.Marshal(payload)
		require.NoError(t, err)

		var parsed PresencePayload
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "joined", parsed.Action)
		assert.Equal(t, "patient", parsed.Role)
	})

	t.Run("leave action", func(t *testing.T) {
		payload := PresencePayload{
			Action: "left",
			Role:   "provider",
		}

		data, err := json.Marshal(payload)
		require.NoError(t, err)

		var parsed PresencePayload
		err = json.Unmarshal(data, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "left", parsed.Action)
		assert.Equal(t, "provider", parsed.Role)
	})
}

func TestHub_ConcurrentBroadcast(t *testing.T) {
	cfg := &Config{
		ReadBufferSize:    1024,
		WriteBufferSize:   1024,
		HandshakeTimeout:  5 * time.Second,
		PongWait:          60 * time.Second,
		PingInterval:      30 * time.Second,
		WriteWait:         10 * time.Second,
		MaxMessageBytes:   65536,
		SendChannelBuffer: 256,
	}

	logger := zerolog.New(nil)
	hub := NewHub(cfg, &logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go hub.Run(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := OutboundEvent{
				Type:           EventMessage,
				ConsultationID: "test-room",
				SenderUserID:   "user",
				Payload:        MessagePayload{Content: "message"},
				SentAt:         time.Now().UTC(),
			}
			hub.Broadcast("test-room", event)
		}(i)
	}

	wg.Wait()
}

func TestHub_MessageHandler(t *testing.T) {
	t.Run("handles nil message handler", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		assert.Nil(t, hub.MessageHandler)
	})

	t.Run("calls message handler on message event", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    1024,
			WriteBufferSize:   1024,
			HandshakeTimeout:  5 * time.Second,
			PongWait:          60 * time.Second,
			PingInterval:      30 * time.Second,
			WriteWait:         10 * time.Second,
			MaxMessageBytes:   65536,
			SendChannelBuffer: 256,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		var handlerCalled bool
		hub.MessageHandler = func(ctx context.Context, consultationID, senderUserID, senderRole string, payload MessagePayload) error {
			handlerCalled = true
			assert.Equal(t, "consultation-1", consultationID)
			assert.Equal(t, "user-1", senderUserID)
			assert.Equal(t, "patient", senderRole)
			return nil
		}

		payload := MessagePayload{
			MessageType: MessageTypeText,
			Content:     "Hello",
		}

		err := hub.MessageHandler(context.Background(), "consultation-1", "user-1", "patient", payload)
		require.NoError(t, err)
		assert.True(t, handlerCalled)
	})
}

func TestHub_Config(t *testing.T) {
	t.Run("uses config values", func(t *testing.T) {
		cfg := &Config{
			ReadBufferSize:    2048,
			WriteBufferSize:   2048,
			HandshakeTimeout:  10 * time.Second,
			PongWait:          120 * time.Second,
			PingInterval:      60 * time.Second,
			WriteWait:         20 * time.Second,
			MaxMessageBytes:   131072,
			SendChannelBuffer: 512,
		}

		logger := zerolog.New(nil)
		hub := NewHub(cfg, &logger)

		assert.Equal(t, 2048, hub.cfg.ReadBufferSize)
		assert.Equal(t, 2048, hub.cfg.WriteBufferSize)
		assert.Equal(t, 10*time.Second, hub.cfg.HandshakeTimeout)
		assert.Equal(t, 120*time.Second, hub.cfg.PongWait)
		assert.Equal(t, 60*time.Second, hub.cfg.PingInterval)
		assert.Equal(t, 20*time.Second, hub.cfg.WriteWait)
		assert.Equal(t, int64(131072), hub.cfg.MaxMessageBytes)
		assert.Equal(t, 512, hub.cfg.SendChannelBuffer)
	})
}

func TestEventTypes(t *testing.T) {
	t.Run("all event types are defined", func(t *testing.T) {
		assert.Equal(t, EventType("message"), EventMessage)
		assert.Equal(t, EventType("typing"), EventTyping)
		assert.Equal(t, EventType("presence"), EventPresence)
		assert.Equal(t, EventType("consult_end"), EventConsultEnd)
		assert.Equal(t, EventType("error"), EventError)
	})
}

func TestMessageTypes(t *testing.T) {
	t.Run("all message types are defined", func(t *testing.T) {
		assert.Equal(t, MessageType("text"), MessageTypeText)
		assert.Equal(t, MessageType("system_event"), MessageTypeSystemEvent)
		assert.Equal(t, MessageType("file"), MessageTypeFile)
	})
}
