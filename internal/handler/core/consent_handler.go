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

type ConsentHandler struct {
	consentService service.ConsentService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewConsentHandler creates a new consent handler
func NewConsentHandler(
	consentService service.ConsentService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ConsentHandler {
	return &ConsentHandler{
		consentService: consentService,
		logger:         logger,
		timeout:        timeout,
	}
}

// GetPrivacyConsent gets privacy consent for a user
func (h *ConsentHandler) GetPrivacyConsent(w http.ResponseWriter, r *http.Request) {
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

	consent, err := h.consentService.GetPrivacyConsent(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToPrivacyConsentResponse(consent))
}

// CreatePrivacyConsent creates privacy consent for a user
func (h *ConsentHandler) CreatePrivacyConsent(w http.ResponseWriter, r *http.Request) {
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

	var req core.PrivacyConsentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	if req.HealthDataConsent && req.HealthDataConsentVersion == "" {
		v.AddError("health_data_consent_version", "Required when health data consent is true")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert request to domain model
	consent := core.ToPrivacyConsent(req)
	consent.UserID = userID

	createdConsent, err := h.consentService.CreatePrivacyConsent(ctx, consent)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, core.ToPrivacyConsentResponse(createdConsent))
}

// UpdatePrivacyConsent updates privacy consent for a user
func (h *ConsentHandler) UpdatePrivacyConsent(w http.ResponseWriter, r *http.Request) {
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

	var req core.PrivacyConsentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	if req.HealthDataConsent && req.HealthDataConsentVersion == "" {
		v.AddError("health_data_consent_version", "Required when health data consent is true")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert request to domain model
	consent := core.ToPrivacyConsent(req)
	consent.UserID = userID

	if err := h.consentService.UpdatePrivacyConsent(ctx, consent); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated consent
	updatedConsent, err := h.consentService.GetPrivacyConsent(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToPrivacyConsentResponse(updatedConsent))
}

// WithdrawConsent withdraws all consents for a user
func (h *ConsentHandler) WithdrawConsent(w http.ResponseWriter, r *http.Request) {
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
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("reason", req.Reason)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.consentService.WithdrawConsent(ctx, userID, req.Reason); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Consent withdrawn successfully",
	})
}

// UpdateHealthDataConsent updates health data consent
func (h *ConsentHandler) UpdateHealthDataConsent(w http.ResponseWriter, r *http.Request) {
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
		Consent bool   `json:"consent"`
		Version string `json:"version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	if req.Consent {
		v.ValidateRequired("version", req.Version)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.consentService.UpdateHealthDataConsent(ctx, userID, req.Consent, req.Version); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Health data consent updated successfully",
	})
}

// UpdateResearchConsent updates research consent
func (h *ConsentHandler) UpdateResearchConsent(w http.ResponseWriter, r *http.Request) {
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
		Consent bool `json:"consent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	if err := h.consentService.UpdateResearchConsent(ctx, userID, req.Consent); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Research consent updated successfully",
	})
}

// UpdateEmergencyAccessConsent updates emergency access consent
func (h *ConsentHandler) UpdateEmergencyAccessConsent(w http.ResponseWriter, r *http.Request) {
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
		Consent bool `json:"consent"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	if err := h.consentService.UpdateEmergencyAccessConsent(ctx, userID, req.Consent); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Emergency access consent updated successfully",
	})
}

// UpdateCommunicationConsents updates communication consents
func (h *ConsentHandler) UpdateCommunicationConsents(w http.ResponseWriter, r *http.Request) {
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
		SMS   bool `json:"sms"`
		Email bool `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	if err := h.consentService.UpdateCommunicationConsents(ctx, userID, req.SMS, req.Email); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Communication consents updated successfully",
	})
}

// GetConsentHistory gets consent history for a user
func (h *ConsentHandler) GetConsentHistory(w http.ResponseWriter, r *http.Request) {
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

	history, err := h.consentService.GetConsentHistory(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	consentResponses := make([]core.PrivacyConsentResponse, len(history))
	for i, consent := range history {
		consentResponses[i] = core.ToPrivacyConsentResponse(consent)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"consent_history": consentResponses,
		"count":           len(consentResponses),
		"user_id":         userID,
	})
}

// ExportConsentData exports consent data for a user
func (h *ConsentHandler) ExportConsentData(w http.ResponseWriter, r *http.Request) {
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

	data, err := h.consentService.ExportConsentData(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Set appropriate headers based on format
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=consent_data_"+userID.String()+".csv")
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=consent_data_"+userID.String()+".json")
	case "xml":
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "attachment; filename=consent_data_"+userID.String()+".xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=consent_data_"+userID.String())
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// NotifyConsentExpirations notifies users of expiring consents (admin endpoint)
func (h *ConsentHandler) NotifyConsentExpirations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	daysBeforeStr := r.URL.Query().Get("days_before")
	daysBefore := 7 // Default 7 days

	if daysBeforeStr != "" {
		if parsedDays, err := strconv.Atoi(daysBeforeStr); err == nil && parsedDays > 0 {
			daysBefore = parsedDays
			if daysBefore > 30 {
				daysBefore = 30 // Max 30 days
			}
		}
	}

	userIDs, err := h.consentService.NotifyConsentExpirations(ctx, daysBefore)
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
		"user_ids":    userIDStrings,
		"count":       len(userIDs),
		"days_before": daysBefore,
		"message":     "Consent expiration notifications processed",
	})
}

// GetActiveConsentsByType gets active consents by type (admin endpoint)
func (h *ConsentHandler) GetActiveConsentsByType(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consentType := r.URL.Query().Get("type")
	if consentType == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "type parameter is required",
		})
		return
	}

	consents, err := h.consentService.GetActiveConsentsByType(ctx, consentType)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	consentResponses := make([]core.PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = core.ToPrivacyConsentResponse(consent)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"consents":     consentResponses,
		"count":        len(consentResponses),
		"consent_type": consentType,
	})
}

// GetExpiredConsents gets expired consents (admin endpoint)
func (h *ConsentHandler) GetExpiredConsents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consents, err := h.consentService.GetExpiredConsents(ctx)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	consentResponses := make([]core.PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = core.ToPrivacyConsentResponse(consent)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"expired_consents": consentResponses,
		"count":            len(consentResponses),
	})
}

// GetWithdrawnConsents gets withdrawn consents within a date range (admin endpoint)
func (h *ConsentHandler) GetWithdrawnConsents(w http.ResponseWriter, r *http.Request) {
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

	consents, err := h.consentService.GetWithdrawnConsents(ctx, startDate, endDate)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	consentResponses := make([]core.PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = core.ToPrivacyConsentResponse(consent)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"withdrawn_consents": consentResponses,
		"count":              len(consentResponses),
		"start_date":         startDate,
		"end_date":           endDate,
	})
}
