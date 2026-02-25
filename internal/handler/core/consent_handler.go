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
