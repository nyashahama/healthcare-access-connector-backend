package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type CredentialHandler struct {
	credentialService service.CredentialService
	logger            *zerolog.Logger
	timeout           time.Duration
}

// NewCredentialHandler creates a new credential handler
func NewCredentialHandler(
	credentialService service.CredentialService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *CredentialHandler {
	return &CredentialHandler{
		credentialService: credentialService,
		logger:            logger,
		timeout:           timeout,
	}
}

// CreateCredential handles credential creation
func (h *CredentialHandler) CreateCredential(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req providers.CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("credential_type", req.CredentialType)
	v.ValidateEnum("credential_type", req.CredentialType, []string{
		"professional_license",
		"specialization",
		"degree",
		"certification",
	})
	v.ValidateRequired("issuing_authority", req.IssuingAuthority)
	v.ValidateMinLength("issuing_authority", req.IssuingAuthority, 1)
	v.ValidateEnum("status", req.Status, []string{
		"verified",
		"pending",
		"expired",
		"revoked",
	})

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert DTO to domain model
	credential := providers.ToDomainCredential(req)

	// Create credential
	createdCredential, err := h.credentialService.CreateCredential(ctx, credential)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, providers.ToCredentialResponse(createdCredential))
}

// GetStaffCredentials handles getting all credentials for a staff member
func (h *CredentialHandler) GetStaffCredentials(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffIDStr := chi.URLParam(r, "staff_id")
	staffID, err := uuid.Parse(staffIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid staff ID format",
		})
		return
	}

	credentials, err := h.credentialService.GetStaffCredentials(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := providers.CredentialListResponse{
		Credentials: make([]providers.CredentialResponse, len(credentials)),
		Total:       len(credentials),
	}

	for i, cred := range credentials {
		response.Credentials[i] = providers.ToCredentialResponse(cred)
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// DeleteCredential handles credential deletion
func (h *CredentialHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	credentialIDStr := chi.URLParam(r, "id")
	credentialID, err := uuid.Parse(credentialIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid credential ID format",
		})
		return
	}

	if err := h.credentialService.DeleteCredential(ctx, credentialID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Credential deleted successfully",
	})
}
