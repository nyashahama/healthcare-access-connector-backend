package core

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type NotificationHandler struct {
	notificationService service.NotificationService
	logger              *zerolog.Logger
	timeout             time.Duration
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(
	notificationService service.NotificationService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *NotificationHandler {
	return &NotificationHandler{
		notificationService: notificationService,
		logger:              logger,
		timeout:             timeout,
	}
}

// GetPreferences gets notification preferences for a user
func (h *NotificationHandler) GetPreferences(w http.ResponseWriter, r *http.Request) {
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

	prefs, err := h.notificationService.GetPreferences(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToNotificationPreferencesResponse(prefs))
}

// UpdatePreferences updates notification preferences for a user
func (h *NotificationHandler) UpdatePreferences(w http.ResponseWriter, r *http.Request) {
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

	var req core.NotificationPreferencesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()

	if req.HealthTipsFrequency != "" {
		validFrequencies := []string{"daily", "weekly", "monthly", "never"}
		v.ValidateEnum("health_tips_frequency", req.HealthTipsFrequency, validFrequencies)
	}

	if req.AppointmentReminderHoursBefore != nil && *req.AppointmentReminderHoursBefore < 0 {
		v.AddError("appointment_reminder_hours_before", "Must be positive or zero")
	}

	if req.NotificationLanguage != "" {
		validLanguages := []string{"en", "af", "zu", "xh"}
		v.ValidateEnum("notification_language", req.NotificationLanguage, validLanguages)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert request to domain model
	prefs := core.ToNotificationPreferences(req)
	prefs.UserID = userID

	if err := h.notificationService.UpdatePreferences(ctx, prefs); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated preferences
	updatedPrefs, err := h.notificationService.GetPreferences(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToNotificationPreferencesResponse(updatedPrefs))
}
