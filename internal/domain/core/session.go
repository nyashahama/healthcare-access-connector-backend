package core

import (
	"time"

	"github.com/google/uuid"
)

// UserSession represents a user session
type UserSession struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	SessionToken string    `json:"session_token"`
	DeviceType   *string   `json:"device_type,omitempty"` // web, mobile_ios, mobile_android, sms
	DeviceID     *string   `json:"device_id,omitempty"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	UserAgent    *string   `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}