package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type ClinicHandler struct {
	clinicService service.ClinicService
	logger        *zerolog.Logger
	timeout       time.Duration
}

// NewClinicHandler creates a new clinic handler
func NewClinicHandler(
	clinicService service.ClinicService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ClinicHandler {
	return &ClinicHandler{
		clinicService: clinicService,
		logger:        logger,
		timeout:       timeout,
	}
}

// CreateClinic handles clinic creation
func (h *ClinicHandler) CreateClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.CreateClinicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("clinic_name", req.ClinicName)
	v.ValidateMinLength("clinic_name", req.ClinicName, 1)
	v.ValidateRequired("clinic_type", req.ClinicType)
	v.ValidateEnum("clinic_type", req.ClinicType, []string{
		"public_health_clinic",
		"private_clinic",
		"community_health_center",
		"mobile_clinic",
	})
	v.ValidateRequired("physical_address", req.PhysicalAddress)
	v.ValidateMinLength("physical_address", req.PhysicalAddress, 1)
	v.ValidateRequired("country", req.Country)

	if req.Email != nil && *req.Email != "" {
		v.ValidateEmail("email", *req.Email)
	}
	if req.PrimaryPhone != nil && *req.PrimaryPhone != "" {
		v.ValidatePhone("primary_phone", *req.PrimaryPhone)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert DTO to domain model
	clinic := dto.ToDomainClinic(req)

	// Create clinic
	createdClinic, err := h.clinicService.CreateClinic(ctx, clinic)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, dto.ToClinicResponse(createdClinic))
}

// GetClinic handles getting a clinic by ID
func (h *ClinicHandler) GetClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	clinic, err := h.clinicService.GetClinicByID(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, dto.ToClinicResponse(clinic))
}

// UpdateClinic handles clinic updates
func (h *ClinicHandler) UpdateClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	var req dto.UpdateClinicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("clinic_name", req.ClinicName)
	v.ValidateMinLength("clinic_name", req.ClinicName, 1)
	v.ValidateRequired("clinic_type", req.ClinicType)
	v.ValidateEnum("clinic_type", req.ClinicType, []string{
		"public_health_clinic",
		"private_clinic",
		"community_health_center",
		"mobile_clinic",
	})
	v.ValidateRequired("physical_address", req.PhysicalAddress)
	v.ValidateMinLength("physical_address", req.PhysicalAddress, 1)
	v.ValidateRequired("country", req.Country)

	if req.Email != nil && *req.Email != "" {
		v.ValidateEmail("email", *req.Email)
	}
	if req.PrimaryPhone != nil && *req.PrimaryPhone != "" {
		v.ValidatePhone("primary_phone", *req.PrimaryPhone)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Get existing clinic
	existing, err := h.clinicService.GetClinicByID(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Update clinic with new data
	updated := dto.UpdateToDomainClinic(existing, req)

	// Update clinic
	if err := h.clinicService.UpdateClinic(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Fetch updated clinic
	updatedClinic, err := h.clinicService.GetClinicByID(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, dto.ToClinicResponse(updatedClinic))
}

// DeleteClinic handles clinic deletion
func (h *ClinicHandler) DeleteClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	if err := h.clinicService.DeleteClinic(ctx, clinicID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Clinic deleted successfully",
	})
}

// VerifyClinic handles clinic verification
func (h *ClinicHandler) VerifyClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	var req dto.VerifyClinicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("notes", req.Notes)
	v.ValidateMinLength("notes", req.Notes, 1)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.clinicService.VerifyClinic(ctx, clinicID, req.VerifiedBy, req.Notes); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Clinic verified successfully",
	})
}

// UpdateVerificationStatus handles updating clinic verification status
func (h *ClinicHandler) UpdateVerificationStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	var req dto.UpdateVerificationStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("status", req.Status)
	v.ValidateEnum("status", req.Status, []string{
		"pending",
		"verified",
		"rejected",
		"in_review",
		"unverified",
	})

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.clinicService.UpdateClinicVerificationStatus(ctx, clinicID, req.Status); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Verification status updated successfully",
	})
}

// DeactivateClinic handles clinic deactivation
func (h *ClinicHandler) DeactivateClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	if err := h.clinicService.DeactivateClinic(ctx, clinicID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Clinic deactivated successfully",
	})
}

// ReactivateClinic handles clinic reactivation
func (h *ClinicHandler) ReactivateClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	if err := h.clinicService.ReactivateClinic(ctx, clinicID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Clinic reactivated successfully",
	})
}

// SearchClinics handles searching for clinics
func (h *ClinicHandler) SearchClinics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Parse query parameters
	query := r.URL.Query().Get("q")
	province := r.URL.Query().Get("province")
	city := r.URL.Query().Get("city")
	clinicType := r.URL.Query().Get("clinic_type")

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// Create search params
	searchParams := providers.ClinicSearchParams{
		Query:      query,
		Province:   stringToPtr(province),
		City:       stringToPtr(city),
		ClinicType: stringToPtr(clinicType),
		Limit:      limit,
		Offset:     offset,
	}

	results, err := h.clinicService.SearchClinics(ctx, searchParams)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	response := make([]dto.ClinicResponse, len(results))
	for i, result := range results {
		response[i] = dto.ToClinicResponse(result.Clinic)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"results": response,
		"count":   len(response),
		"limit":   limit,
		"offset":  offset,
	})
}

// ListClinics handles listing clinics with filters
func (h *ClinicHandler) ListClinics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	offset := 0
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	clinics, err := h.clinicService.GetClinics(ctx)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	response := make([]dto.ClinicResponse, len(clinics))
	for i, clinic := range clinics {
		response[i] = dto.ToClinicResponse(clinic)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"clinics": response,
		"count":   len(response),
		"limit":   limit,
		"offset":  offset,
	})
}

func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
