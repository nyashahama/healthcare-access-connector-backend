package core

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
)

// SessionResponse represents a user session in responses
type SessionResponse struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	SessionToken string    `json:"session_token,omitempty"` // Omit in list responses for security
	DeviceType   *string   `json:"device_type,omitempty"`
	DeviceID     *string   `json:"device_id,omitempty"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	UserAgent    *string   `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	IsActive     bool      `json:"is_active"`
	TimeToExpiry *string   `json:"time_to_expiry,omitempty"` // Human readable time until expiry
}

// SessionListResponse represents a list of sessions
type SessionListResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Count    int               `json:"count"`
	UserID   uuid.UUID         `json:"user_id"`
}

// CreateSessionRequest represents request to create a new session
type CreateSessionRequest struct {
	UserID     uuid.UUID `json:"user_id" validate:"required"`
	DeviceType *string   `json:"device_type,omitempty"`
	DeviceID   *string   `json:"device_id,omitempty"`
	IPAddress  *string   `json:"ip_address,omitempty"`
	UserAgent  *string   `json:"user_agent,omitempty"`
	ExpiresIn  int       `json:"expires_in,omitempty"` // Duration in hours, default 24
}

// RevokeSessionRequest represents request to revoke a session
type RevokeSessionRequest struct {
	Token string `json:"token" validate:"required"`
}

// RevokeAllExceptCurrentRequest represents request to revoke all sessions except current
type RevokeAllExceptCurrentRequest struct {
	CurrentSessionID string `json:"current_session_id" validate:"required"`
}

// InvalidateDeviceSessionRequest represents request to invalidate a device session
type InvalidateDeviceSessionRequest struct {
	DeviceID string `json:"device_id" validate:"required"`
}

// UpdateSessionTokenRequest represents request to update/rotate a session token
type UpdateSessionTokenRequest struct {
	NewToken  string    `json:"new_token" validate:"required"`
	ExpiresAt time.Time `json:"expires_at" validate:"required"`
}

// ValidateSessionRequest represents request to validate a session
type ValidateSessionRequest struct {
	Token  string `json:"token" validate:"required"`
	Extend *int   `json:"extend,omitempty"` // Duration in hours to extend if close to expiry
}

// SessionCountResponse represents response for session count
type SessionCountResponse struct {
	UserID uuid.UUID `json:"user_id"`
	Count  int       `json:"count"`
}

// SessionValidationResponse represents response for session validation
type SessionValidationResponse struct {
	Valid     bool             `json:"valid"`
	Session   *SessionResponse `json:"session,omitempty"`
	Extended  bool             `json:"extended,omitempty"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
}

// ToSessionResponse converts domain.UserSession to SessionResponse
func ToSessionResponse(session core.UserSession) SessionResponse {
	now := time.Now()
	isActive := session.ExpiresAt.After(now)

	var timeToExpiry *string
	if isActive {
		duration := session.ExpiresAt.Sub(now)
		formatted := formatDuration(duration)
		timeToExpiry = &formatted
	}

	return SessionResponse{
		ID:           session.ID,
		UserID:       session.UserID,
		SessionToken: "", // Don't expose token in response for security
		DeviceType:   session.DeviceType,
		DeviceID:     session.DeviceID,
		IPAddress:    session.IPAddress,
		UserAgent:    session.UserAgent,
		ExpiresAt:    session.ExpiresAt,
		CreatedAt:    session.CreatedAt,
		IsActive:     isActive,
		TimeToExpiry: timeToExpiry,
	}
}

// ToSessionResponseWithToken converts domain.UserSession to SessionResponse including token
// Use only for authentication responses where the token needs to be returned
func ToSessionResponseWithToken(session core.UserSession) SessionResponse {
	resp := ToSessionResponse(session)
	resp.SessionToken = session.SessionToken
	return resp
}

// ToSessionListResponse converts list of sessions to SessionListResponse
func ToSessionListResponse(sessions []core.UserSession, userID uuid.UUID) SessionListResponse {
	sessionResponses := make([]SessionResponse, len(sessions))
	for i, session := range sessions {
		sessionResponses[i] = ToSessionResponse(session)
	}

	return SessionListResponse{
		Sessions: sessionResponses,
		Count:    len(sessionResponses),
		UserID:   userID,
	}
}

// ToCreateSessionDomain converts CreateSessionRequest to domain.UserSession
func ToCreateSessionDomain(req CreateSessionRequest, token string, expiresAt time.Time) core.UserSession {
	return core.UserSession{
		ID:           uuid.New(),
		UserID:       req.UserID,
		SessionToken: token,
		DeviceType:   req.DeviceType,
		DeviceID:     req.DeviceID,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}
}

// Helper function to format duration in human-readable format
func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 24 {
		days := hours / 24
		remainingHours := hours % 24
		if remainingHours > 0 {
			return fmt.Sprintf("%d days, %d hours", days, remainingHours)
		}
		return fmt.Sprintf("%d days", days)
	}

	if hours > 0 {
		if minutes > 0 {
			return fmt.Sprintf("%d hours, %d minutes", hours, minutes)
		}
		return fmt.Sprintf("%d hours", hours)
	}

	if minutes > 0 {
		return fmt.Sprintf("%d minutes", minutes)
	}

	seconds := int(d.Seconds())
	return fmt.Sprintf("%d seconds", seconds)
}
