package providers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
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

	// Get claims from context using the middleware helper
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Extract user ID from claims
	userID := claims.UserID

	// Determine owner user ID (default to current user if not specified in request)
	ownerUserID := userID
	if req.OwnerUserID != nil {
		ownerUserID = *req.OwnerUserID
	}

	// Convert DTO to domain model
	clinic := dto.ToDomainClinic(req)

	// Create clinic with owner tracking
	createdClinic, err := h.clinicService.RegisterClinic(ctx, clinic, userID, ownerUserID)
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
// func (h *ClinicHandler) UpdateVerificationStatus(w http.ResponseWriter, r *http.Request) {
// 	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
// 	defer cancel()
//
// 	clinicIDStr := chi.URLParam(r, "id")
// 	clinicID, err := uuid.Parse(clinicIDStr)
// 	if err != nil {
// 		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
// 			Error: "Invalid clinic ID format",
// 		})
// 		return
// 	}
//
// 	var req dto.UpdateVerificationStatusRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
// 			Error: "Invalid request body",
// 		})
// 		return
// 	}
//
// 	// Validate input
// 	v := validator.New()
// 	v.ValidateRequired("status", req.Status)
// 	v.ValidateEnum("status", req.Status, []string{
// 		"pending",
// 		"verified",
// 		"rejected",
// 		"in_review",
// 		"unverified",
// 	})
//
// 	if !v.Valid() {
// 		handler.RespondValidationError(w, v.Errors())
// 		return
// 	}
//
// 	if err := h.clinicService.UpdateClinicVerificationStatus(ctx, clinicID, req.Status); err != nil {
// 		handler.RespondError(w, h.logger, err)
// 		return
// 	}
//
// 	handler.RespondJSON(w, http.StatusOK, map[string]string{
// 		"message": "Verification status updated successfully",
// 	})
// }

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

// Add UpdateClinicOwner handler
func (h *ClinicHandler) UpdateClinicOwner(w http.ResponseWriter, r *http.Request) {
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

	// Get the user making the request from context
	updatedBy, ok := ctx.Value("user_id").(uuid.UUID)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Parse request body
	var req struct {
		NewOwnerUserID uuid.UUID `json:"new_owner_user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("new_owner_user_id", req.NewOwnerUserID.String())

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Update clinic owner
	if err := h.clinicService.UpdateClinicOwner(ctx, clinicID, req.NewOwnerUserID, updatedBy); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Clinic owner updated successfully",
	})
}

// Add GetClinicByOwner handler
func (h *ClinicHandler) GetClinicByOwner(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get owner user ID from query parameter
	ownerUserIDStr := r.URL.Query().Get("owner_user_id")
	if ownerUserIDStr == "" {
		// If not specified, get from authenticated user context
		userID, ok := ctx.Value("user_id").(uuid.UUID)
		if !ok {
			handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
				Error: "Owner user ID is required",
			})
			return
		}
		ownerUserIDStr = userID.String()
	}

	ownerUserID, err := uuid.Parse(ownerUserIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid owner user ID format",
		})
		return
	}

	// Get clinic by owner
	clinic, err := h.clinicService.GetClinicByOwner(ctx, ownerUserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, dto.ToClinicResponse(*clinic))
}

// Add GetClinicWithOwnerInfo handler
func (h *ClinicHandler) GetClinicWithOwnerInfo(w http.ResponseWriter, r *http.Request) {
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

	// Get clinic with owner information
	clinicWithOwner, err := h.clinicService.GetClinicWithOwnerInfo(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, dto.ToClinicWithOwnerResponse(*clinicWithOwner))
}

// Add GetClinicVerificationStatus handler
func (h *ClinicHandler) GetClinicVerificationStatus(w http.ResponseWriter, r *http.Request) {
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

	// Get verification status
	verification, err := h.clinicService.GetClinicVerificationStatus(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, verification)
}

// GetMyClinic handles getting the current user's clinic
func (h *ClinicHandler) GetMyClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get user from context using middleware helper
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Get user ID from claims
	userID := claims.UserID

	// Get clinic by owner
	clinic, err := h.clinicService.GetClinicByOwner(ctx, userID)
	if err != nil {
		// Check if it's a "not found" error
		if errors.Is(err, domain.ErrClinicNotFound) {
			handler.RespondJSON(w, http.StatusNotFound, dto.ErrorResponse{
				Error: "No clinic found for this user",
			})
			return
		}
		handler.RespondError(w, h.logger, err)
		return
	}

	// Return clinic in the expected format for frontend
	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"clinic": dto.ToClinicResponse(*clinic),
	})
}

func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
