// Package ws provides the WebSocket hub for telemedicine real-time chat
package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// MessageType mirrors the consultation_messages.message_type enum in the schema
type MessageType string

const (
	MessageTypeText        MessageType = "text"
	MessageTypeSystemEvent MessageType = "system_event"
	MessageTypeFile        MessageType = "file"
)

// EventType describes the envelope event sent over the WebSocket
type EventType string

const (
	EventMessage    EventType = "message"     // new chat message
	EventTyping     EventType = "typing"      // user is typing
	EventPresence   EventType = "presence"    // join / leave
	EventConsultEnd EventType = "consult_end" // consultation closed
	EventError      EventType = "error"       // server-side error
)

// InboundEvent is the JSON envelope the client sends to the server
type InboundEvent struct {
	Type           EventType       `json:"type"`
	ConsultationID string          `json:"consultation_id"`
	Payload        json.RawMessage `json:"payload,omitempty"`
}

// OutboundEvent is the JSON envelope the server sends to clients
type OutboundEvent struct {
	Type           EventType   `json:"type"`
	ConsultationID string      `json:"consultation_id"`
	SenderUserID   string      `json:"sender_user_id,omitempty"`
	Payload        interface{} `json:"payload,omitempty"`
	SentAt         time.Time   `json:"sent_at"`
}

// MessagePayload is the payload for EventMessage
type MessagePayload struct {
	MessageID   string      `json:"message_id,omitempty"` // set by server after DB persist
	MessageType MessageType `json:"message_type"`
	Content     string      `json:"content"`
	Metadata    interface{} `json:"metadata,omitempty"`
}

// PresencePayload is the payload for EventPresence
type PresencePayload struct {
	Action string `json:"action"` // "joined" | "left"
	Role   string `json:"role"`   // "patient" | "provider"
}

// client represents a single WebSocket connection
type client struct {
	hub            *Hub
	conn           *websocket.Conn
	send           chan []byte
	userID         string
	role           string
	consultationID string
}

// Hub manages all active WebSocket connections, keyed by consultation ID
type Hub struct {
	cfg    *Config
	logger *zerolog.Logger

	// rooms maps consultationID -> set of connected clients
	rooms   map[string]map[*client]struct{}
	roomsMu sync.RWMutex

	// MessageHandler is called for every validated inbound message.
	// Implementations should persist to DB, then call hub.Broadcast.
	// Signature: (ctx, consultationID, senderUserID, senderRole, payload) error
	MessageHandler func(ctx context.Context, consultationID, senderUserID, senderRole string, payload MessagePayload) error

	register   chan *client
	unregister chan *client

	upgrader websocket.Upgrader
}

// NewHub creates a Hub.  Call hub.Run() in a goroutine before serving requests.
func NewHub(cfg *Config, logger *zerolog.Logger) *Hub {
	h := &Hub{
		cfg:    cfg,
		logger: logger,
		rooms:  make(map[string]map[*client]struct{}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:   cfg.ReadBufferSize,
			WriteBufferSize:  cfg.WriteBufferSize,
			HandshakeTimeout: cfg.HandshakeTimeout,
			CheckOrigin: func(r *http.Request) bool {
				// Delegate origin checking to the CORS middleware already on the router
				return true
			},
		},
		register:   make(chan *client, 64),
		unregister: make(chan *client, 64),
	}
	return h
}

// Run processes hub-level events.  Must be called once in a dedicated goroutine.
func (h *Hub) Run(ctx context.Context) {
	h.logger.Info().Msg("WebSocket hub started")
	for {
		select {
		case <-ctx.Done():
			h.logger.Info().Msg("WebSocket hub stopping")
			return

		case c := <-h.register:
			h.roomsMu.Lock()
			if _, ok := h.rooms[c.consultationID]; !ok {
				h.rooms[c.consultationID] = make(map[*client]struct{})
			}
			h.rooms[c.consultationID][c] = struct{}{}
			h.roomsMu.Unlock()

			h.logger.Info().
				Str("user_id", c.userID).
				Str("role", c.role).
				Str("consultation_id", c.consultationID).
				Msg("WebSocket client joined")

			// Broadcast presence event to the room
			h.broadcastRaw(c.consultationID, OutboundEvent{
				Type:           EventPresence,
				ConsultationID: c.consultationID,
				SenderUserID:   c.userID,
				SentAt:         time.Now().UTC(),
				Payload:        PresencePayload{Action: "joined", Role: c.role},
			})

		case c := <-h.unregister:
			h.roomsMu.Lock()
			if room, ok := h.rooms[c.consultationID]; ok {
				delete(room, c)
				if len(room) == 0 {
					delete(h.rooms, c.consultationID)
				}
			}
			h.roomsMu.Unlock()
			close(c.send)

			h.logger.Info().
				Str("user_id", c.userID).
				Str("consultation_id", c.consultationID).
				Msg("WebSocket client left")

			h.broadcastRaw(c.consultationID, OutboundEvent{
				Type:           EventPresence,
				ConsultationID: c.consultationID,
				SenderUserID:   c.userID,
				SentAt:         time.Now().UTC(),
				Payload:        PresencePayload{Action: "left", Role: c.role},
			})
		}
	}
}

// ServeWS upgrades the HTTP connection and registers the client with the hub.
//
// URL params expected by the handler:
//
//	consultationID – the UUID from the consultations table
//	userID         – authenticated user ID (extracted from JWT claims by the caller)
//	role           – "patient" | "provider"
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, consultationID, userID, role string) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}

	c := &client{
		hub:            h,
		conn:           conn,
		send:           make(chan []byte, h.cfg.SendChannelBuffer),
		userID:         userID,
		role:           role,
		consultationID: consultationID,
	}

	h.register <- c

	// Start writer and reader goroutines
	go c.writePump(h.cfg)
	go c.readPump(h)
}

// Broadcast sends an OutboundEvent to all clients in the given consultation room.
// Call this from your MessageHandler after persisting to DB.
func (h *Hub) Broadcast(consultationID string, event OutboundEvent) {
	h.broadcastRaw(consultationID, event)
}

// broadcastRaw serialises and fans out to the room (skips empty rooms silently)
func (h *Hub) broadcastRaw(consultationID string, event OutboundEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		h.logger.Error().Err(err).Msg("WebSocket: failed to marshal event")
		return
	}

	h.roomsMu.RLock()
	room := h.rooms[consultationID]
	h.roomsMu.RUnlock()

	for c := range room {
		select {
		case c.send <- data:
		default:
			// Slow client — drop and unregister
			h.unregister <- c
		}
	}
}

// RoomSize returns the number of connected clients in a consultation room.
// Useful for availability / max_concurrent_consultations enforcement.
func (h *Hub) RoomSize(consultationID string) int {
	h.roomsMu.RLock()
	defer h.roomsMu.RUnlock()
	return len(h.rooms[consultationID])
}

// IsAvailable always returns true when the hub is running
func (h *Hub) IsAvailable() bool { return true }

// =============================================================================
// client pump goroutines
// =============================================================================

func (c *client) readPump(h *Hub) {
	defer func() {
		h.unregister <- c
		if err := c.conn.Close(); err != nil {
			h.logger.Warn().Err(err).Msg("failed to close websocket connection (read pump)")
		}
	}()

	c.conn.SetReadLimit(h.cfg.MaxMessageBytes)
	_ = c.conn.SetReadDeadline(time.Now().Add(h.cfg.PongWait))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(h.cfg.PongWait))
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				h.logger.Warn().Err(err).Str("user_id", c.userID).Msg("WebSocket read error")
			}
			return
		}

		var event InboundEvent
		if err := json.Unmarshal(data, &event); err != nil {
			h.sendError(c, "invalid JSON payload")
			continue
		}

		// Validate the client is operating on its own consultation
		if event.ConsultationID != c.consultationID {
			h.sendError(c, "consultation_id mismatch")
			continue
		}

		switch event.Type {
		case EventMessage:
			var payload MessagePayload
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				h.sendError(c, "invalid message payload")
				continue
			}

			if h.MessageHandler != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := h.MessageHandler(ctx, c.consultationID, c.userID, c.role, payload); err != nil {
					h.logger.Error().Err(err).Msg("WebSocket: MessageHandler error")
					h.sendError(c, fmt.Sprintf("message not saved: %v", err))
				}
				cancel()
			}

		case EventTyping:
			// Fan-out typing indicator to everyone else in the room
			h.broadcastRaw(c.consultationID, OutboundEvent{
				Type:           EventTyping,
				ConsultationID: c.consultationID,
				SenderUserID:   c.userID,
				SentAt:         time.Now().UTC(),
			})

		case EventConsultEnd:
			// Broadcast end event; actual DB update is the service layer's job
			h.broadcastRaw(c.consultationID, OutboundEvent{
				Type:           EventConsultEnd,
				ConsultationID: c.consultationID,
				SenderUserID:   c.userID,
				SentAt:         time.Now().UTC(),
			})

		default:
			h.sendError(c, "unknown event type: "+string(event.Type))
		}
	}
}

func (c *client) writePump(cfg *Config) {
	ticker := time.NewTicker(cfg.PingInterval)
	defer func() {
		ticker.Stop()
		if err := c.conn.Close(); err != nil {
			c.hub.logger.Warn().Err(err).Msg("failed to close websocket connection (write pump)")
		}
	}()

	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(cfg.WriteWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(cfg.WriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *Hub) sendError(c *client, msg string) {
	data, _ := json.Marshal(OutboundEvent{
		Type:    EventError,
		SentAt:  time.Now().UTC(),
		Payload: map[string]string{"error": msg},
	})
	select {
	case c.send <- data:
	default:
	}
}
