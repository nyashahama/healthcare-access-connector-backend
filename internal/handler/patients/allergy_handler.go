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

type AllergyHandler struct {
	allergyService service.AllergyService
	logger         *zerolog.Logger
	timeout        time.Duration
}

func NewAllergyHandler(allergyService service.AllergyService, logger *zerolog.Logger, timeout time.Duration) *AllergyHandler {
	return &AllergyHandler{allergyService: allergyService, logger: logger, timeout: timeout}
}

func (h *AllergyHandler) RegisterRoutes(router chi.Router) {
	router.Route("/allergies", func(r chi.Router) {
		r.Post("/", h.CreateAllergy)
		r.Get("/patient/{patientID}", h.GetPatientAllergies)
		r.Get("/patient/{patientID}/active", h.GetActiveAllergies)
		r.Put("/{id}", h.UpdateAllergy)
		r.Delete("/{id}", h.DeleteAllergy)
	})
}

func (h *AllergyHandler) CreateAllergy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateAllergyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("allergy_name", req.AllergyName)
	v.ValidateRequired("severity", req.Severity)
	v.ValidateRequired("status", req.Status)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	allergy := pat_dto.ToDomainAllergy(req)
	created, err := h.allergyService.AddPatientAllergy(ctx, allergy)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToAllergyResponse(created))
}

func (h *AllergyHandler) GetPatientAllergies(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	allergies, err := h.allergyService.GetPatientAllergies(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.AllergyResponse, len(allergies))
	for i, allergy := range allergies {
		responses[i] = pat_dto.ToAllergyResponse(allergy)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.AllergiesListResponse{Allergies: responses, Count: len(responses)})
}

func (h *AllergyHandler) GetActiveAllergies(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	allergies, err := h.allergyService.GetActivePatientAllergies(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.AllergyResponse, len(allergies))
	for i, allergy := range allergies {
		responses[i] = pat_dto.ToAllergyResponse(allergy)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.AllergiesListResponse{Allergies: responses, Count: len(responses)})
}

func (h *AllergyHandler) UpdateAllergy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	allergyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid allergy ID format"})
		return
	}

	var req pat_dto.UpdateAllergyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("allergy_name", req.AllergyName)
	v.ValidateRequired("severity", req.Severity)
	v.ValidateRequired("status", req.Status)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	patientID, err := uuid.Parse(r.URL.Query().Get("patient_id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Patient ID is required"})
		return
	}

	allergies, err := h.allergyService.GetPatientAllergies(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.AllergyResponse
	for _, allergy := range allergies {
		if allergy.ID == allergyID {
			resp := pat_dto.ToAllergyResponse(allergy)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{Error: "Allergy not found"})
		return
	}

	existingDomain := pat_dto.ToDomainAllergy(pat_dto.CreateAllergyRequest{
		PatientID:           existing.PatientID,
		AllergyName:         existing.AllergyName,
		Severity:            existing.Severity,
		ReactionDescription: existing.ReactionDescription,
		FirstIdentifiedDate: existing.FirstIdentifiedDate,
		LastOccurrenceDate:  existing.LastOccurrenceDate,
		Status:              existing.Status,
		Notes:               existing.Notes,
	})
	existingDomain.ID = existing.ID

	updated := pat_dto.UpdateToDomainAllergy(existingDomain, req)
	if err := h.allergyService.UpdatePatientAllergy(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	updatedAllergies, err := h.allergyService.GetPatientAllergies(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, allergy := range updatedAllergies {
		if allergy.ID == allergyID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToAllergyResponse(allergy))
			return
		}
	}
}

func (h *AllergyHandler) DeleteAllergy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	allergyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid allergy ID format"})
		return
	}

	if err := h.allergyService.DeletePatientAllergy(ctx, allergyID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{"message": "Allergy deleted successfully"})
}
