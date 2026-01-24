package patients

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	pat_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type PatientHandler struct {
	patientService service.PatientService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewPatientHandler creates a new patient handler
func NewPatientHandler(
	patientService service.PatientService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *PatientHandler {
	return &PatientHandler{
		patientService: patientService,
		logger:         logger,
		timeout:        timeout,
	}
}

// RegisterRoutes registers patient routes
func (h *PatientHandler) RegisterRoutes(router chi.Router) {
	router.Route("/patients", func(r chi.Router) {
		r.Post("/", h.CreatePatientProfile)
		r.Get("/search", h.SearchPatients)
		r.Get("/demographics", h.GetDemographicsSummary)
		r.Get("/national-id/{nationalID}", h.GetPatientByNationalID)

		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", h.GetPatientProfile)
			r.Put("/", h.UpdatePatientProfile)
			r.Delete("/", h.DeletePatientProfile)
		})

		r.Route("/user/{userID}", func(r chi.Router) {
			r.Get("/", h.GetPatientByUserID)
			r.Delete("/", h.DeletePatientProfileByUserID)
		})
	})
}

// CreatePatientProfile handles creation of a new patient profile
func (h *PatientHandler) CreatePatientProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreatePatientProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("user_id", req.UserID.String())
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateRequired("last_name", req.LastName)
	v.ValidateRequired("country", req.Country)

	if req.NationalIDNumber != nil && len(*req.NationalIDNumber) > 0 {
		v.ValidateMinLength("national_id_number", *req.NationalIDNumber, 13)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert to domain model
	profile := pat_dto.ToDomainPatientProfile(req)

	// Create patient profile
	created, err := h.patientService.CreatePatientProfile(ctx, profile)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToPatientProfileResponse(created))
}

// GetPatientProfile handles retrieval of a patient profile by ID
func (h *PatientHandler) GetPatientProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "id")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid patient ID format",
		})
		return
	}

	// Get patient profile
	profile, err := h.patientService.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToPatientProfileResponse(profile))
}

// GetPatientByUserID handles retrieval of a patient profile by user ID
func (h *PatientHandler) GetPatientByUserID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	// Get patient profile by user ID
	profile, err := h.patientService.GetPatientProfile(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToPatientProfileResponse(profile))
}

// GetPatientByNationalID handles retrieval of a patient profile by national ID
func (h *PatientHandler) GetPatientByNationalID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	nationalID := chi.URLParam(r, "nationalID")
	if nationalID == "" {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "National ID is required",
		})
		return
	}

	// Get patient profile by national ID
	profile, err := h.patientService.GetPatientProfileByNationalID(ctx, nationalID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToPatientProfileResponse(profile))
}

// UpdatePatientProfile handles updating a patient profile
func (h *PatientHandler) UpdatePatientProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "id")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid patient ID format",
		})
		return
	}

	var req pat_dto.UpdatePatientProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateRequired("last_name", req.LastName)
	v.ValidateRequired("country", req.Country)

	if req.NationalIDNumber != nil && len(*req.NationalIDNumber) > 0 {
		v.ValidateMinLength("national_id_number", *req.NationalIDNumber, 13)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Get existing profile
	existing, err := h.patientService.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Update profile with new data
	updated := pat_dto.UpdateToDomainPatientProfile(existing, req)

	// Update patient profile
	if err := h.patientService.UpdatePatientProfile(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated profile
	profile, err := h.patientService.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToPatientProfileResponse(profile))
}

// DeletePatientProfile handles deletion of a patient profile
func (h *PatientHandler) DeletePatientProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "id")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid patient ID format",
		})
		return
	}

	if err := h.patientService.DeletePatientProfile(ctx, patientID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Patient profile deleted successfully",
	})
}

// DeletePatientProfileByUserID handles deletion of a patient profile by user ID
func (h *PatientHandler) DeletePatientProfileByUserID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "userID")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	if err := h.patientService.DeletePatientProfileByUserID(ctx, userID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Patient profile deleted successfully",
	})
}

// SearchPatients handles searching for patients with filters
func (h *PatientHandler) SearchPatients(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Parse query parameters
	params := patients.AdvancedSearchParams{
		Query:               stringPtr(r.URL.Query().Get("q")),
		Province:            stringPtr(r.URL.Query().Get("province")),
		City:                stringPtr(r.URL.Query().Get("city")),
		Gender:              stringPtr(r.URL.Query().Get("gender")),
		CommunicationMethod: stringPtr(r.URL.Query().Get("communication_method")),
		EmploymentStatus:    stringPtr(r.URL.Query().Get("employment_status")),
		MedicalAidProvider:  stringPtr(r.URL.Query().Get("medical_aid_provider")),
	}

	// Parse boolean parameters
	if hasMedicalAid := r.URL.Query().Get("has_medical_aid"); hasMedicalAid != "" {
		val, err := strconv.ParseBool(hasMedicalAid)
		if err == nil {
			params.HasMedicalAid = &val
		}
	}
	if requiresInterpreter := r.URL.Query().Get("requires_interpreter"); requiresInterpreter != "" {
		val, err := strconv.ParseBool(requiresInterpreter)
		if err == nil {
			params.RequiresInterpreter = &val
		}
	}
	if acceptsMarketingEmails := r.URL.Query().Get("accepts_marketing_emails"); acceptsMarketingEmails != "" {
		val, err := strconv.ParseBool(acceptsMarketingEmails)
		if err == nil {
			params.AcceptsMarketingEmails = &val
		}
	}

	// Parse pagination parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // Default limit
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
			if limit > 100 {
				limit = 100 // Max limit
			}
		}
	}

	offset := 0
	if offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	params.Limit = limit
	params.Offset = offset

	// Search patients
	profiles, err := h.patientService.SearchPatients(ctx, params)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.PatientProfileResponse, len(profiles))
	for i, profile := range profiles {
		responses[i] = pat_dto.ToPatientProfileResponse(profile)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.SearchPatientsResponse{
		Patients: responses,
		Count:    len(responses),
		Total:    len(responses), // In a real implementation, this would be the total count
		Limit:    limit,
		Offset:   offset,
	})
}

// GetDemographicsSummary handles retrieval of patient demographics summary
func (h *PatientHandler) GetDemographicsSummary(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	summary, err := h.patientService.GetDemographicsSummary(ctx)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.DemographicsResponse{
		Summary: summary,
	})
}

// Helper function to convert string to string pointer
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
