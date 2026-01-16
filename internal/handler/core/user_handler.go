package core

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type UserHandler struct {
	userService service.UserService
	logger      *zerolog.Logger
	timeout     time.Duration
}

// NewUserHandler creates a new user handler
func NewUserHandler(
	userService service.UserService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
		timeout:     timeout,
	}
}

// GetProfile retrieves user's profile
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
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

	// Get user profile using user service
	user, patientProfile, err := h.userService.GetProfile(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToProfileResponse(user, patientProfile))
}

// GetConsent retrieves user consent settings
func (h *UserHandler) GetConsent(w http.ResponseWriter, r *http.Request) {
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

	// Get consent
	consent, err := h.userService.GetConsent(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := core.ConsentResponse{
		HealthDataConsent:         consent.HealthDataConsent,
		ResearchConsent:           consent.ResearchConsent,
		EmergencyAccessConsent:    consent.EmergencyAccessConsent,
		SMSCommunicationConsent:   consent.SMSCommunicationConsent,
		EmailCommunicationConsent: consent.EmailCommunicationConsent,
		ConsentWithdrawn:          consent.ConsentWithdrawn,
		ConsentDate:               consent.HealthDataConsentDate,
		CreatedAt:                 consent.CreatedAt,
		UpdatedAt:                 consent.UpdatedAt,
	}

	handler.RespondJSON(w, http.StatusOK, response)
}
