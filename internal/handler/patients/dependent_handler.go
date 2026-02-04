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

type ConditionHandler struct {
	conditionService service.ConditionService
	logger           *zerolog.Logger
	timeout          time.Duration
}

func NewConditionHandler(conditionService service.ConditionService, logger *zerolog.Logger, timeout time.Duration) *ConditionHandler {
	return &ConditionHandler{conditionService: conditionService, logger: logger, timeout: timeout}
}

func (h *ConditionHandler) RegisterRoutes(router chi.Router) {
	router.Route("/conditions", func(r chi.Router) {
		r.Post("/", h.CreateCondition)
		r.Get("/patient/{patientID}", h.GetPatientConditions)
		r.Get("/patient/{patientID}/active", h.GetActiveConditions)
		r.Put("/{id}", h.UpdateCondition)
		r.Delete("/{id}", h.DeleteCondition)
	})
}

func (h *ConditionHandler) CreateCondition(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateConditionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("condition_name", req.ConditionName)
	v.ValidateRequired("status", req.Status)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	condition := pat_dto.ToDomainCondition(req)
	created, err := h.conditionService.AddPatientCondition(ctx, condition)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToConditionResponse(created))
}

func (h *ConditionHandler) GetPatientConditions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	var status *string
	if statusParam := r.URL.Query().Get("status"); statusParam != "" {
		status = &statusParam
	}

	conditions, err := h.conditionService.GetPatientConditions(ctx, patientID, status)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.ConditionResponse, len(conditions))
	for i, condition := range conditions {
		responses[i] = pat_dto.ToConditionResponse(condition)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ConditionsListResponse{Conditions: responses, Count: len(responses)})
}

func (h *ConditionHandler) GetActiveConditions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	conditions, err := h.conditionService.GetActiveConditions(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.ConditionResponse, len(conditions))
	for i, condition := range conditions {
		responses[i] = pat_dto.ToConditionResponse(condition)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ConditionsListResponse{Conditions: responses, Count: len(responses)})
}

func (h *ConditionHandler) UpdateCondition(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	conditionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid condition ID format"})
		return
	}

	var req pat_dto.UpdateConditionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("condition_name", req.ConditionName)
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

	conditions, err := h.conditionService.GetPatientConditions(ctx, patientID, nil)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.ConditionResponse
	for _, condition := range conditions {
		if condition.ID == conditionID {
			resp := pat_dto.ToConditionResponse(condition)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{Error: "Condition not found"})
		return
	}

	existingDomain := pat_dto.ToDomainCondition(pat_dto.CreateConditionRequest{
		PatientID:       existing.PatientID,
		ConditionName:   existing.ConditionName,
		ICD10Code:       existing.ICD10Code,
		Type:            existing.Type,
		DiagnosedDate:   existing.DiagnosedDate,
		DiagnosedBy:     existing.DiagnosedBy,
		Severity:        existing.Severity,
		Status:          existing.Status,
		Notes:           existing.Notes,
		LastFlareUp:     existing.LastFlareUp,
		NextCheckupDate: existing.NextCheckupDate,
	})
	existingDomain.ID = existing.ID

	updated := pat_dto.UpdateToDomainCondition(existingDomain, req)
	if err := h.conditionService.UpdatePatientCondition(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	updatedConditions, err := h.conditionService.GetPatientConditions(ctx, patientID, nil)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, condition := range updatedConditions {
		if condition.ID == conditionID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToConditionResponse(condition))
			return
		}
	}
}

func (h *ConditionHandler) DeleteCondition(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	conditionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid condition ID format"})
		return
	}

	if err := h.conditionService.DeletePatientCondition(ctx, conditionID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{"message": "Condition deleted successfully"})
}
