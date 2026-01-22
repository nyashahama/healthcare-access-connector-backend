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

// CreatePreferences creates notification preferences for a user
func (h *NotificationHandler) CreatePreferences(w http.ResponseWriter, r *http.Request) {
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

	createdPrefs, err := h.notificationService.CreatePreferences(ctx, prefs)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, core.ToNotificationPreferencesResponse(createdPrefs))
}

// UpdateChannelSettings updates notification channel settings
func (h *NotificationHandler) UpdateChannelSettings(w http.ResponseWriter, r *http.Request) {
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
		SMSEnabled   bool `json:"sms_enabled"`
		EmailEnabled bool `json:"email_enabled"`
		PushEnabled  bool `json:"push_enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	if err := h.notificationService.UpdateChannelSettings(ctx, userID, req.SMSEnabled, req.EmailEnabled, req.PushEnabled); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Notification channel settings updated successfully",
	})
}

// UpdateAppointmentReminders updates appointment reminder settings
func (h *NotificationHandler) UpdateAppointmentReminders(w http.ResponseWriter, r *http.Request) {
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
		Enabled     bool `json:"enabled"`
		HoursBefore int  `json:"hours_before"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	if req.HoursBefore < 1 {
		v.AddError("hours_before", "Must be at least 1")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.notificationService.UpdateAppointmentReminders(ctx, userID, req.Enabled, req.HoursBefore); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Appointment reminder settings updated successfully",
	})
}

// UpdateHealthTips updates health tips settings
func (h *NotificationHandler) UpdateHealthTips(w http.ResponseWriter, r *http.Request) {
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
		Enabled   bool   `json:"enabled"`
		Frequency string `json:"frequency"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	validFrequencies := []string{"daily", "weekly", "monthly", "never"}
	v.ValidateEnum("frequency", req.Frequency, validFrequencies)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.notificationService.UpdateHealthTips(ctx, userID, req.Enabled, req.Frequency); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Health tips settings updated successfully",
	})
}

// SetQuietHours sets quiet hours for notifications
func (h *NotificationHandler) SetQuietHours(w http.ResponseWriter, r *http.Request) {
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
		StartTime *string `json:"start_time"` // Format: "HH:MM:SS"
		EndTime   *string `json:"end_time"`   // Format: "HH:MM:SS"
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Parse time strings
	var startTime, endTime *time.Time
	if req.StartTime != nil {
		if t, err := time.Parse("15:04:05", *req.StartTime); err == nil {
			startTime = &t
		} else {
			handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
				Error: "Invalid start time format. Use HH:MM:SS",
			})
			return
		}
	}
	if req.EndTime != nil {
		if t, err := time.Parse("15:04:05", *req.EndTime); err == nil {
			endTime = &t
		} else {
			handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
				Error: "Invalid end time format. Use HH:MM:SS",
			})
			return
		}
	}

	if err := h.notificationService.SetQuietHours(ctx, userID, startTime, endTime); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Quiet hours set successfully",
	})
}

// CanSendNotification checks if a notification can be sent to a user
func (h *NotificationHandler) CanSendNotification(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := r.URL.Query().Get("user_id")
	notificationType := r.URL.Query().Get("type")
	channel := r.URL.Query().Get("channel")

	if userIDStr == "" || notificationType == "" || channel == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "user_id, type, and channel parameters are required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	canSend, err := h.notificationService.CanSendNotification(ctx, userID, notificationType, channel)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"can_send":          canSend,
		"user_id":           userID,
		"notification_type": notificationType,
		"channel":           channel,
		"timestamp":         time.Now(),
	})
}

// GetUsersWithDisabledNotifications gets users who have disabled a specific notification type
func (h *NotificationHandler) GetUsersWithDisabledNotifications(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	notificationType := r.URL.Query().Get("type")
	if notificationType == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "type parameter is required",
		})
		return
	}

	userIDs, err := h.notificationService.GetUsersWithDisabledNotifications(ctx, notificationType)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert UUIDs to strings
	userIDStrings := make([]string, len(userIDs))
	for i, id := range userIDs {
		userIDStrings[i] = id.String()
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"user_ids":          userIDStrings,
		"count":             len(userIDs),
		"notification_type": notificationType,
	})
}
