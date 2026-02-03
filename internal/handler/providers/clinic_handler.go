package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	domainmodels "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
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

	var req providers.CreateClinicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
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
	clinic := domainmodels.Clinic{
		ClinicName:             req.ClinicName,
		ClinicType:             req.ClinicType,
		RegistrationNumber:     req.RegistrationNumber,
		AccreditationNumber:    req.AccreditationNumber,
		PrimaryPhone:           req.PrimaryPhone,
		SecondaryPhone:         req.SecondaryPhone,
		EmergencyPhone:         req.EmergencyPhone,
		Email:                  req.Email,
		Website:                req.Website,
		PhysicalAddress:        req.PhysicalAddress,
		City:                   req.City,
		Province:               req.Province,
		PostalCode:             req.PostalCode,
		Country:                req.Country,
		Latitude:               req.Latitude,
		Longitude:              req.Longitude,
		GooglePlaceID:          req.GooglePlaceID,
		Description:            req.Description,
		YearEstablished:        req.YearEstablished,
		OwnershipType:          req.OwnershipType,
		BedCount:               req.BedCount,
		OperatingHours:         req.OperatingHours,
		Services:               req.Services,
		Specialties:            req.Specialties,
		LanguagesSpoken:        req.LanguagesSpoken,
		Facilities:             req.Facilities,
		AcceptsMedicalAid:      req.AcceptsMedicalAid,
		MedicalAidProviders:    req.MedicalAidProviders,
		PaymentMethods:         req.PaymentMethods,
		FeeStructure:           req.FeeStructure,
		AccreditationBody:      req.AccreditationBody,
		AccreditationExpiry:    req.AccreditationExpiry,
		Certifications:         req.Certifications,
		PatientCapacity:        req.PatientCapacity,
		AverageWaitTimeMinutes: req.AverageWaitTimeMinutes,
		ContactPersonName:      req.ContactPersonName,
		ContactPersonRole:      req.ContactPersonRole,
		ContactPersonPhone:     req.ContactPersonPhone,
		ContactPersonEmail:     req.ContactPersonEmail,
	}

	// Create clinic
	createdClinic, err := h.clinicService.CreateClinic(ctx, clinic)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, providers.ClinicToResponse(createdClinic))
}

// GetClinic handles getting a clinic by ID
func (h *ClinicHandler) GetClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	clinic, err := h.clinicService.GetClinicByID(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ClinicToResponse(clinic))
}

// UpdateClinic handles clinic updates
func (h *ClinicHandler) UpdateClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	var req providers.UpdateClinicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
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
	clinic := domainmodels.Clinic{
		ID:                     clinicID,
		ClinicName:             req.ClinicName,
		ClinicType:             req.ClinicType,
		RegistrationNumber:     req.RegistrationNumber,
		AccreditationNumber:    req.AccreditationNumber,
		PrimaryPhone:           req.PrimaryPhone,
		SecondaryPhone:         req.SecondaryPhone,
		EmergencyPhone:         req.EmergencyPhone,
		Email:                  req.Email,
		Website:                req.Website,
		PhysicalAddress:        req.PhysicalAddress,
		City:                   req.City,
		Province:               req.Province,
		PostalCode:             req.PostalCode,
		Country:                req.Country,
		Latitude:               req.Latitude,
		Longitude:              req.Longitude,
		GooglePlaceID:          req.GooglePlaceID,
		Description:            req.Description,
		YearEstablished:        req.YearEstablished,
		OwnershipType:          req.OwnershipType,
		BedCount:               req.BedCount,
		OperatingHours:         req.OperatingHours,
		Services:               req.Services,
		Specialties:            req.Specialties,
		LanguagesSpoken:        req.LanguagesSpoken,
		Facilities:             req.Facilities,
		AcceptsMedicalAid:      req.AcceptsMedicalAid,
		MedicalAidProviders:    req.MedicalAidProviders,
		PaymentMethods:         req.PaymentMethods,
		FeeStructure:           req.FeeStructure,
		AccreditationBody:      req.AccreditationBody,
		AccreditationExpiry:    req.AccreditationExpiry,
		Certifications:         req.Certifications,
		PatientCapacity:        req.PatientCapacity,
		AverageWaitTimeMinutes: req.AverageWaitTimeMinutes,
		ContactPersonName:      req.ContactPersonName,
		ContactPersonRole:      req.ContactPersonRole,
		ContactPersonPhone:     req.ContactPersonPhone,
		ContactPersonEmail:     req.ContactPersonEmail,
	}

	// Update clinic
	if err := h.clinicService.UpdateClinic(ctx, clinic); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Fetch updated clinic
	updatedClinic, err := h.clinicService.GetClinicByID(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ClinicToResponse(updatedClinic))
}

// DeleteClinic handles clinic deletion
func (h *ClinicHandler) DeleteClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
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

// ListClinics handles listing clinics with pagination
// func (h *ClinicHandler) ListClinics(w http.ResponseWriter, r *http.Request) {
// 	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
// 	defer cancel()
//
// 	// Parse query parameters
// 	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
// 	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
// 	clinicType := r.URL.Query().Get("clinic_type")
// 	isVerified := r.URL.Query().Get("is_verified")
//
// 	if limit <= 0 {
// 		limit = 20
// 	}
// 	if limit > 100 {
// 		limit = 100
// 	}
//
// 	// Build filters
// 	filters := make(map[string]interface{})
// 	if clinicType != "" {
// 		filters["clinic_type"] = clinicType
// 	}
// 	if isVerified == "true" {
// 		filters["is_verified"] = true
// 	} else if isVerified == "false" {
// 		filters["is_verified"] = false
// 	}
//
// 	clinics, total, err := h.clinicService.GetClinics(ctx, filters, limit, offset)
// 	if err != nil {
// 		handler.RespondError(w, h.logger, err)
// 		return
// 	}
//
// 	response := providers.ClinicListResponse{
// 		Clinics: make([]providers.ClinicResponse, len(clinics)),
// 		Total:   total,
// 		Limit:   limit,
// 		Offset:  offset,
// 	}
//
// 	for i, clinic := range clinics {
// 		response.Clinics[i] = providers.ClinicToResponse(clinic)
// 	}
//
// 	handler.RespondJSON(w, http.StatusOK, response)
// }

// VerifyClinic handles clinic verification
func (h *ClinicHandler) VerifyClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	var req providers.VerifyClinicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
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
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	var req providers.UpdateVerificationStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
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

// SearchClinics handles clinic search
// func (h *ClinicHandler) SearchClinics(w http.ResponseWriter, r *http.Request) {
// 	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
// 	defer cancel()
//
// 	query := r.URL.Query().Get("q")
// 	if query == "" {
// 		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
// 			Error: "Search query is required",
// 		})
// 		return
// 	}
//
// 	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
// 	if limit <= 0 {
// 		limit = 20
// 	}
// 	if limit > 100 {
// 		limit = 100
// 	}
//
// 	results, total, err := h.clinicService.SearchClinics(ctx, query, limit)
// 	if err != nil {
// 		handler.RespondError(w, h.logger, err)
// 		return
// 	}
//
// 	response := providers.ClinicSearchResponse{
// 		Results: results,
// 		Total:   total,
// 		Query:   query,
// 	}
//
// 	handler.RespondJSON(w, http.StatusOK, response)
// }
