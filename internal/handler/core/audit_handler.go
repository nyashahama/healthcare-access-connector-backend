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

// GetActivitiesByType retrieves activities by type within a date range
func (h *AuditHandler) GetActivitiesByType(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	activityType := chi.URLParam(r, "type")
	if activityType == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Activity type is required",
		})
		return
	}

	// Parse query parameters
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	// Default to last 30 days
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	if startDateStr != "" {
		if parsedStart, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			startDate = parsedStart
		}
	}

	if endDateStr != "" {
		if parsedEnd, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			endDate = parsedEnd
		}
	}

	activities, err := h.auditService.GetActivitiesByType(ctx, activityType, startDate, endDate)
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
		"type":       activityType,
		"start_date": startDate,
		"end_date":   endDate,
	})
}

// GetDataAccessLogs retrieves data access logs for a user
func (h *AuditHandler) GetDataAccessLogs(w http.ResponseWriter, r *http.Request) {
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

	logs, err := h.auditService.GetDataAccessLogs(ctx, userID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	logResponses := make([]core.DataAccessLogResponse, len(logs))
	for i, log := range logs {
		logResponses[i] = core.ToDataAccessLogResponse(log)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"access_logs": logResponses,
		"count":       len(logResponses),
		"limit":       limit,
		"offset":      offset,
		"user_id":     userID,
	})
}

// GetEmergencyAccessLogs retrieves emergency access logs
func (h *AuditHandler) GetEmergencyAccessLogs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

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

	logs, err := h.auditService.GetEmergencyAccessLogs(ctx, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	logResponses := make([]core.DataAccessLogResponse, len(logs))
	for i, log := range logs {
		logResponses[i] = core.ToDataAccessLogResponse(log)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"emergency_access_logs": logResponses,
		"count":                 len(logResponses),
		"limit":                 limit,
		"offset":                offset,
	})
}

// GetSuspiciousActivities retrieves suspicious activities
func (h *AuditHandler) GetSuspiciousActivities(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	thresholdStr := r.URL.Query().Get("threshold")
	threshold := 50 // Default threshold

	if thresholdStr != "" {
		if parsedThreshold, err := strconv.Atoi(thresholdStr); err == nil && parsedThreshold > 0 {
			threshold = parsedThreshold
		}
	}

	activities, err := h.auditService.GetSuspiciousActivities(ctx, threshold)
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
		"suspicious_activities": activityResponses,
		"count":                 len(activityResponses),
		"threshold":             threshold,
	})
}

// GetFailedLoginAttempts retrieves failed login attempts
func (h *AuditHandler) GetFailedLoginAttempts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := r.URL.Query().Get("user_id")
	withinStr := r.URL.Query().Get("within")

	var userID *uuid.UUID
	if userIDStr != "" {
		if parsedID, err := uuid.Parse(userIDStr); err == nil {
			userID = &parsedID
		}
	}

	within := 24 * time.Hour // Default 24 hours
	if withinStr != "" {
		if parsedHours, err := strconv.Atoi(withinStr); err == nil && parsedHours > 0 {
			within = time.Duration(parsedHours) * time.Hour
		}
	}

	attempts, err := h.auditService.GetFailedLoginAttempts(ctx, userID, within)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	attemptResponses := make([]core.UserActivityResponse, len(attempts))
	for i, attempt := range attempts {
		attemptResponses[i] = core.ToUserActivityResponse(attempt)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"failed_login_attempts": attemptResponses,
		"count":                 len(attemptResponses),
		"within_hours":          within.Hours(),
		"user_id":               userID,
	})
}

// GenerateAccessReport generates an access report for a user
func (h *AuditHandler) GenerateAccessReport(w http.ResponseWriter, r *http.Request) {
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
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	// Default to last 30 days
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	if startDateStr != "" {
		if parsedStart, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			startDate = parsedStart
		}
	}

	if endDateStr != "" {
		if parsedEnd, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			endDate = parsedEnd
		}
	}

	report, err := h.auditService.GenerateAccessReport(ctx, userID, startDate, endDate)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"report":     report,
		"user_id":    userID,
		"start_date": startDate,
		"end_date":   endDate,
	})
}

// GenerateActivityReport generates an activity report
func (h *AuditHandler) GenerateActivityReport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Parse query parameters
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")

	// Default to last 30 days
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -30)

	if startDateStr != "" {
		if parsedStart, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			startDate = parsedStart
		}
	}

	if endDateStr != "" {
		if parsedEnd, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			endDate = parsedEnd
		}
	}

	report, err := h.auditService.GenerateActivityReport(ctx, startDate, endDate)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"report":     report,
		"start_date": startDate,
		"end_date":   endDate,
	})
}

// ExportUserAuditTrail exports user audit trail
func (h *AuditHandler) ExportUserAuditTrail(w http.ResponseWriter, r *http.Request) {
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

	// Get the export format (default: JSON)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, err := h.auditService.ExportUserAuditTrail(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Set appropriate headers based on format
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_trail_"+userID.String()+".csv")
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_trail_"+userID.String()+".json")
	case "xml":
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_trail_"+userID.String()+".xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_trail_"+userID.String())
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
