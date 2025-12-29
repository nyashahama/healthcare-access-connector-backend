package core

import (
	"time"

	"github.com/google/uuid"
)

// OTPVerification represents one-time password verification for password reset
type OTPVerification struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	OTP       string     `json:"otp"`     // 6-digit code
	Type      string     `json:"type"`    // "password_reset", "email_verification"
	Channel   string     `json:"channel"` // "email", "sms"
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}