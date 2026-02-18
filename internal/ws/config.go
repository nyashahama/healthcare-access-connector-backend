// Package ws provides WebSocket configuration for the telemedicine hub
package ws

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all WebSocket hub tuning parameters
type Config struct {
	// ReadBufferSize is the gorilla/websocket read buffer in bytes (default 4096)
	ReadBufferSize int

	// WriteBufferSize is the gorilla/websocket write buffer in bytes (default 4096)
	WriteBufferSize int

	// MaxMessageBytes is the maximum inbound message size in bytes (default 8192)
	// Prevents memory exhaustion from oversized payloads
	MaxMessageBytes int64

	// SendChannelBuffer is the per-client outbound channel depth (default 256)
	SendChannelBuffer int

	// PingInterval is how often the server sends a ping to the client (default 30s)
	// Must be less than PongWait
	PingInterval time.Duration

	// PongWait is how long the server waits for a pong reply (default 60s)
	PongWait time.Duration

	// WriteWait is the timeout for a single write operation (default 10s)
	WriteWait time.Duration

	// HandshakeTimeout is the WebSocket upgrade handshake timeout (default 10s)
	HandshakeTimeout time.Duration
}

// ConfigFromEnv loads WebSocket config from environment variables.
//
// Env vars:
//
//	WS_READ_BUFFER_SIZE    – int bytes,    default 4096
//	WS_WRITE_BUFFER_SIZE   – int bytes,    default 4096
//	WS_MAX_MESSAGE_BYTES   – int64 bytes,  default 8192
//	WS_SEND_CHANNEL_BUFFER – int,          default 256
//	WS_PING_INTERVAL       – Go duration,  default 30s
//	WS_PONG_WAIT           – Go duration,  default 60s
//	WS_WRITE_WAIT          – Go duration,  default 10s
//	WS_HANDSHAKE_TIMEOUT   – Go duration,  default 10s
func ConfigFromEnv() *Config {
	return &Config{
		ReadBufferSize:    getEnvAsInt("WS_READ_BUFFER_SIZE", 4096),
		WriteBufferSize:   getEnvAsInt("WS_WRITE_BUFFER_SIZE", 4096),
		MaxMessageBytes:   getEnvAsInt64("WS_MAX_MESSAGE_BYTES", 8192),
		SendChannelBuffer: getEnvAsInt("WS_SEND_CHANNEL_BUFFER", 256),
		PingInterval:      getEnvAsDuration("WS_PING_INTERVAL", 30*time.Second),
		PongWait:          getEnvAsDuration("WS_PONG_WAIT", 60*time.Second),
		WriteWait:         getEnvAsDuration("WS_WRITE_WAIT", 10*time.Second),
		HandshakeTimeout:  getEnvAsDuration("WS_HANDSHAKE_TIMEOUT", 10*time.Second),
	}
}

// Validate checks the config for logical consistency
func (c *Config) Validate() error {
	if c.PingInterval >= c.PongWait {
		return fmt.Errorf("ws: WS_PING_INTERVAL (%s) must be less than WS_PONG_WAIT (%s)",
			c.PingInterval, c.PongWait)
	}
	if c.WriteWait < time.Second {
		return fmt.Errorf("ws: WS_WRITE_WAIT must be at least 1 second")
	}
	if c.MaxMessageBytes < 512 {
		return fmt.Errorf("ws: WS_MAX_MESSAGE_BYTES must be at least 512")
	}
	if c.SendChannelBuffer < 16 {
		return fmt.Errorf("ws: WS_SEND_CHANNEL_BUFFER must be at least 16")
	}
	return nil
}

// helper functions (package-local)

func getEnvAsInt(key string, defaultValue int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(key), 10, 64); err == nil {
		return v
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return v
	}
	return defaultValue
}
