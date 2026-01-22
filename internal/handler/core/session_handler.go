package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type SessionHandler struct {
	sessionService service.SessionService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewSessionHandler creates a new session handler
func NewSessionHandler(
	sessionService service.SessionService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *SessionHandler {
	return &SessionHandler{
		sessionService: sessionService,
		logger:         logger,
		timeout:        timeout,
	}
}

// GetSession retrieves a session by token
func (h *SessionHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := chi.URLParam(r, "token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Session token is required",
		})
		return
	}

	session, err := h.sessionService.GetSession(ctx, token)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToSessionResponse(session))
}

// GetUserSessions retrieves all active sessions for a user
func (h *SessionHandler) GetUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	sessions, err := h.sessionService.GetUserSessions(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	sessionResponses := make([]core.SessionResponse, len(sessions))
	for i, session := range sessions {
		sessionResponses[i] = core.ToSessionResponse(session)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessionResponses,
		"count":    len(sessionResponses),
		"user_id":  userID,
	})
}

// RevokeSession revokes a specific session
func (h *SessionHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Session token is required",
		})
		return
	}

	if err := h.sessionService.RevokeSession(ctx, token, userID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Session revoked successfully",
	})
}

// RevokeAllSessions revokes all sessions for a user
func (h *SessionHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	if err := h.sessionService.RevokeAllSessions(ctx, userID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "All sessions revoked successfully",
	})
}

// RevokeAllExceptCurrent revokes all sessions except the current one
func (h *SessionHandler) RevokeAllExceptCurrent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	var req struct {
		CurrentSessionID string `json:"current_session_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	if req.CurrentSessionID == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Current session ID is required",
		})
		return
	}

	currentSessionID, err := uuid.Parse(req.CurrentSessionID)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid current session ID format",
		})
		return
	}

	if err := h.sessionService.RevokeAllExceptCurrent(ctx, userID, currentSessionID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "All other sessions revoked successfully",
	})
}

// InvalidateSessionByDevice invalidates session by device ID
func (h *SessionHandler) InvalidateSessionByDevice(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Device ID is required",
		})
		return
	}

	if err := h.sessionService.InvalidateSessionByDevice(ctx, userID, deviceID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Device session invalidated successfully",
	})
}

// ValidateAndExtendSession validates a session and optionally extends it
func (h *SessionHandler) ValidateAndExtendSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := chi.URLParam(r, "token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Session token is required",
		})
		return
	}

	extendDurationStr := r.URL.Query().Get("extend")
	extendDuration := 0 * time.Second

	if extendDurationStr != "" {
		if parsedHours, err := strconv.Atoi(extendDurationStr); err == nil && parsedHours > 0 {
			extendDuration = time.Duration(parsedHours) * time.Hour
		}
	}

	session, err := h.sessionService.ValidateAndExtendSession(ctx, token, extendDuration)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToSessionResponse(session))
}

// GetActiveSessionCount gets the count of active sessions for a user
func (h *SessionHandler) GetActiveSessionCount(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	count, err := h.sessionService.GetActiveSessionCount(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"user_id": userID,
		"count":   count,
	})
}

// CleanupExpiredSessions cleans up expired sessions (admin endpoint)
func (h *SessionHandler) CleanupExpiredSessions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if err := h.sessionService.CleanupExpiredSessions(ctx); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Expired sessions cleaned up successfully",
	})
}

// UpdateSessionToken updates a session token (for rotation)
func (h *SessionHandler) UpdateSessionToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	sessionIDStr := chi.URLParam(r, "id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid session ID format",
		})
		return
	}

	var req struct {
		NewToken  string    `json:"new_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("new_token", req.NewToken)
	v.ValidateRequired("expires_at", req.ExpiresAt.String())

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.sessionService.UpdateSessionToken(ctx, sessionID, req.NewToken, req.ExpiresAt); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Session token updated successfully",
	})
}
