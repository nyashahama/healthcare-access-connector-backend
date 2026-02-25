package core

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type AuditHandler struct {
	auditService service.AuditService
	logger       *zerolog.Logger
	timeout      time.Duration
}

// NewAuditHandler creates a new audit handler
func NewAuditHandler(
	auditService service.AuditService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *AuditHandler {
	return &AuditHandler{
		auditService: auditService,
		logger:       logger,
		timeout:      timeout,
	}
}

// GetUserActivities retrieves activities for a user
func (h *AuditHandler) GetUserActivities(w http.ResponseWriter, r *http.Request) {
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

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100 // Default limit
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
			if limit > 1000 {
				limit = 1000 // Max limit
			}
		}
	}

	offset := 0
	if offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	activities, err := h.auditService.GetUserActivities(ctx, userID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	activityResponses := make([]core.UserActivityResponse, len(activities))
	for i, activity := range activities {
		activityResponses[i] = core.ToUserActivityResponse(activity)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"activities": activityResponses,
		"count":      len(activityResponses),
		"limit":      limit,
		"offset":     offset,
		"user_id":    userID,
	})
}
