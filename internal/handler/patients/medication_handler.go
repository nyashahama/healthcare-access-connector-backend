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

type MedicationHandler struct {
	medicationService service.MedicationService
	logger            *zerolog.Logger
	timeout           time.Duration
}

// NewMedicationHandler creates a new medication handler
func NewMedicationHandler(
	medicationService service.MedicationService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *MedicationHandler {
	return &MedicationHandler{
		medicationService: medicationService,
		logger:            logger,
		timeout:           timeout,
	}
}

// RegisterRoutes registers medication routes
func (h *MedicationHandler) RegisterRoutes(router chi.Router) {
	router.Route("/medications", func(r chi.Router) {
		r.Post("/", h.CreateMedication)
		r.Get("/patient/{patientID}", h.GetPatientMedications)
		r.Get("/patient/{patientID}/active", h.GetActiveMedications)
		r.Put("/{id}", h.UpdateMedication)
		r.Delete("/{id}", h.DeleteMedication)
	})
}

func (h *MedicationHandler) CreateMedication(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateMedicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("medication_name", req.MedicationName)
	v.ValidateRequired("status", req.Status)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Create medication
	medication := pat_dto.ToDomainMedication(req)
	created, err := h.medicationService.AddPatientMedication(ctx, medication)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToMedicationResponse(created))
}

func (h *MedicationHandler) GetPatientMedications(w http.ResponseWriter, r *http.Request) {
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

	// Get status filter from query parameter
	var status *string
	if statusParam := r.URL.Query().Get("status"); statusParam != "" {
		status = &statusParam
	}

	// Get medications
	medications, err := h.medicationService.GetPatientMedications(ctx, patientID, status)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.MedicationResponse, len(medications))
	for i, medication := range medications {
		responses[i] = pat_dto.ToMedicationResponse(medication)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.MedicationsListResponse{
		Medications: responses,
		Count:       len(responses),
	})
}

func (h *MedicationHandler) GetActiveMedications(w http.ResponseWriter, r *http.Request) {
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

	// Get active medications
	medications, err := h.medicationService.GetActiveMedications(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.MedicationResponse, len(medications))
	for i, medication := range medications {
		responses[i] = pat_dto.ToMedicationResponse(medication)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.MedicationsListResponse{
		Medications: responses,
		Count:       len(responses),
	})
}

func (h *MedicationHandler) UpdateMedication(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	medicationIDStr := chi.URLParam(r, "id")
	medicationID, err := uuid.Parse(medicationIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid medication ID format",
		})
		return
	}

	var req pat_dto.UpdateMedicationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("medication_name", req.MedicationName)
	v.ValidateRequired("status", req.Status)

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

	// Get existing medications to find the one to update
	medications, err := h.medicationService.GetPatientMedications(ctx, patientID, nil)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.MedicationResponse
	for _, medication := range medications {
		if medication.ID == medicationID {
			resp := pat_dto.ToMedicationResponse(medication)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{
			Error: "Medication not found",
		})
		return
	}

	// Convert existing response back to domain
	existingDomain := pat_dto.ToDomainMedication(pat_dto.CreateMedicationRequest{
		PatientID:           existing.PatientID,
		MedicationName:      existing.MedicationName,
		GenericName:         existing.GenericName,
		Dosage:              existing.Dosage,
		Frequency:           existing.Frequency,
		Route:               existing.Route,
		PrescribingDoctor:   existing.PrescribingDoctor,
		PharmacyName:        existing.PharmacyName,
		PrescriptionDate:    existing.PrescriptionDate,
		StartDate:           existing.StartDate,
		EndDate:             existing.EndDate,
		ReasonForMedication: existing.ReasonForMedication,
		Status:              existing.Status,
		SideEffects:         existing.SideEffects,
		Instructions:        existing.Instructions,
	})
	existingDomain.ID = existing.ID

	// Update medication
	updated := pat_dto.UpdateToDomainMedication(existingDomain, req)
	if err := h.medicationService.UpdatePatientMedication(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated medication
	updatedMedications, err := h.medicationService.GetPatientMedications(ctx, patientID, nil)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, medication := range updatedMedications {
		if medication.ID == medicationID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToMedicationResponse(medication))
			return
		}
	}

	handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{
		Error: "Medication not found after update",
	})
}

func (h *MedicationHandler) DeleteMedication(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	medicationIDStr := chi.URLParam(r, "id")
	medicationID, err := uuid.Parse(medicationIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid medication ID format",
		})
		return
	}

	if err := h.medicationService.DeletePatientMedication(ctx, medicationID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Medication deleted successfully",
	})
}
