package patients

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	pat_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type ImmunizationHandler struct {
	immunizationService service.ImmunizationService
	logger              *zerolog.Logger
	timeout             time.Duration
}

// NewImmunizationHandler creates a new immunization handler
func NewImmunizationHandler(
	immunizationService service.ImmunizationService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ImmunizationHandler {
	return &ImmunizationHandler{
		immunizationService: immunizationService,
		logger:              logger,
		timeout:             timeout,
	}
}

// RegisterRoutes registers immunization routes
func (h *ImmunizationHandler) RegisterRoutes(router chi.Router) {
	router.Route("/immunizations", func(r chi.Router) {
		r.Post("/", h.CreateImmunization)
		r.Get("/patient/{patientID}", h.GetPatientImmunizations)
		r.Get("/patient/{patientID}/upcoming", h.GetUpcomingImmunizations)
		r.Put("/{id}", h.UpdateImmunization)
		r.Delete("/{id}", h.DeleteImmunization)
	})
}

func (h *ImmunizationHandler) CreateImmunization(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateImmunizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("vaccine_name", req.VaccineName)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Create immunization
	immunization := pat_dto.ToDomainImmunization(req)
	created, err := h.immunizationService.AddPatientImmunization(ctx, immunization)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToImmunizationResponse(created))
}

func (h *ImmunizationHandler) GetPatientImmunizations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "patientID")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid patient ID format",
		})
		return
	}

	// Get immunizations
	immunizations, err := h.immunizationService.GetPatientImmunizations(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.ImmunizationResponse, len(immunizations))
	for i, immunization := range immunizations {
		responses[i] = pat_dto.ToImmunizationResponse(immunization)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ImmunizationsListResponse{
		Immunizations: responses,
		Count:         len(responses),
	})
}

func (h *ImmunizationHandler) GetUpcomingImmunizations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "patientID")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid patient ID format",
		})
		return
	}

	// Get upcoming immunizations
	immunizations, err := h.immunizationService.GetUpcomingImmunizations(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.ImmunizationResponse, len(immunizations))
	for i, immunization := range immunizations {
		responses[i] = pat_dto.ToImmunizationResponse(immunization)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ImmunizationsListResponse{
		Immunizations: responses,
		Count:         len(responses),
	})
}

func (h *ImmunizationHandler) UpdateImmunization(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	immunizationIDStr := chi.URLParam(r, "id")
	immunizationID, err := uuid.Parse(immunizationIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid immunization ID format",
		})
		return
	}

	var req pat_dto.UpdateImmunizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("vaccine_name", req.VaccineName)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Get patient ID from query parameter
	patientIDStr := r.URL.Query().Get("patient_id")
	if patientIDStr == "" {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Patient ID is required",
		})
		return
	}

	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid patient ID format",
		})
		return
	}

	// Get existing immunizations to find the one to update
	immunizations, err := h.immunizationService.GetPatientImmunizations(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.ImmunizationResponse
	for _, immunization := range immunizations {
		if immunization.ID == immunizationID {
			resp := pat_dto.ToImmunizationResponse(immunization)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{
			Error: "Immunization not found",
		})
		return
	}

	// Convert existing response back to domain
	existingDomain := pat_dto.ToDomainImmunization(pat_dto.CreateImmunizationRequest{
		PatientID:          existing.PatientID,
		VaccineName:        existing.VaccineName,
		VaccineType:        existing.VaccineType,
		AdministrationDate: existing.AdministrationDate,
		NextDueDate:        existing.NextDueDate,
		AdministeredBy:     existing.AdministeredBy,
		ClinicName:         existing.ClinicName,
		LotNumber:          existing.LotNumber,
		Manufacturer:       existing.Manufacturer,
		DoseNumber:         existing.DoseNumber,
		TotalDoses:         existing.TotalDoses,
		Notes:              existing.Notes,
		DocumentedBy:       existing.DocumentedBy,
	})
	existingDomain.ID = existing.ID

	// Update immunization
	updated := pat_dto.UpdateToDomainImmunization(existingDomain, req)
	if err := h.immunizationService.UpdatePatientImmunization(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated immunization
	updatedImmunizations, err := h.immunizationService.GetPatientImmunizations(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, immunization := range updatedImmunizations {
		if immunization.ID == immunizationID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToImmunizationResponse(immunization))
			return
		}
	}

	handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{
		Error: "Immunization not found after update",
	})
}

func (h *ImmunizationHandler) DeleteImmunization(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	immunizationIDStr := chi.URLParam(r, "id")
	immunizationID, err := uuid.Parse(immunizationIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid immunization ID format",
		})
		return
	}

	if err := h.immunizationService.DeletePatientImmunization(ctx, immunizationID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Immunization deleted successfully",
	})
}
