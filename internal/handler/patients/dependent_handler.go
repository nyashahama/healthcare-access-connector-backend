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

type DependentHandler struct {
	dependentService service.DependentService
	logger           *zerolog.Logger
	timeout          time.Duration
}

func NewDependentHandler(dependentService service.DependentService, logger *zerolog.Logger, timeout time.Duration) *DependentHandler {
	return &DependentHandler{dependentService: dependentService, logger: logger, timeout: timeout}
}

func (h *DependentHandler) RegisterRoutes(router chi.Router) {
	router.Route("/dependents", func(r chi.Router) {
		r.Post("/", h.CreateDependent)
		r.Get("/patient/{patientID}", h.GetPatientDependents)
		r.Get("/patient/{patientID}/children", h.GetDependentChildren)
		r.Put("/{id}", h.UpdateDependent)
		r.Delete("/{id}", h.DeleteDependent)
	})
}

func (h *DependentHandler) CreateDependent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateDependentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateRequired("last_name", req.LastName)
	v.ValidateRequired("relationship", req.Relationship)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	dependent := pat_dto.ToDomainDependent(req)
	created, err := h.dependentService.AddPatientDependent(ctx, dependent)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToDependentResponse(created))
}

func (h *DependentHandler) GetPatientDependents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	dependents, err := h.dependentService.GetPatientDependents(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.DependentResponse, len(dependents))
	for i, dependent := range dependents {
		responses[i] = pat_dto.ToDependentResponse(dependent)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.DependentsListResponse{Dependents: responses, Count: len(responses)})
}

func (h *DependentHandler) GetDependentChildren(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	dependents, err := h.dependentService.GetDependentChildren(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.DependentResponse, len(dependents))
	for i, dependent := range dependents {
		responses[i] = pat_dto.ToDependentResponse(dependent)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.DependentsListResponse{Dependents: responses, Count: len(responses)})
}

func (h *DependentHandler) UpdateDependent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	dependentID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid dependent ID format"})
		return
	}

	var req pat_dto.UpdateDependentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateRequired("last_name", req.LastName)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	patientID, err := uuid.Parse(r.URL.Query().Get("patient_id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Patient ID is required"})
		return
	}

	dependents, err := h.dependentService.GetPatientDependents(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.DependentResponse
	for _, dependent := range dependents {
		if dependent.ID == dependentID {
			resp := pat_dto.ToDependentResponse(dependent)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{Error: "Dependent not found"})
		return
	}

	existingDomain := pat_dto.ToDomainDependent(pat_dto.CreateDependentRequest{
		PatientID:               existing.PatientID,
		FirstName:               existing.FirstName,
		LastName:                existing.LastName,
		DateOfBirth:             existing.DateOfBirth,
		Gender:                  existing.Gender,
		Relationship:            existing.Relationship,
		BloodType:               existing.BloodType,
		HealthStatus:            existing.HealthStatus,
		PrimaryPediatrician:     existing.PrimaryPediatrician,
		ClinicID:                existing.ClinicID,
		BirthWeightKg:           existing.BirthWeightKg,
		BirthHeightCm:           existing.BirthHeightCm,
		SchoolName:              existing.SchoolName,
		Grade:                   existing.Grade,
		HasLegalGuardianship:    existing.HasLegalGuardianship,
		GuardianshipDocumentURL: existing.GuardianshipDocumentURL,
		HasSpecialNeeds:         existing.HasSpecialNeeds,
		SpecialNeedsDescription: existing.SpecialNeedsDescription,
	})
	existingDomain.ID = existing.ID

	updated := pat_dto.UpdateToDomainDependent(existingDomain, req)
	if err := h.dependentService.UpdatePatientDependent(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	updatedDependents, err := h.dependentService.GetPatientDependents(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, dependent := range updatedDependents {
		if dependent.ID == dependentID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToDependentResponse(dependent))
			return
		}
	}
}

func (h *DependentHandler) DeleteDependent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	dependentID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid dependent ID format"})
		return
	}

	if err := h.dependentService.DeletePatientDependent(ctx, dependentID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{"message": "Dependent deleted successfully"})
}
