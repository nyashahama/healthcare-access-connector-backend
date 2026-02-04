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

type FamilyHistoryHandler struct {
	familyHistoryService service.FamilyHistoryService
	logger               *zerolog.Logger
	timeout              time.Duration
}

func NewFamilyHistoryHandler(
	familyHistoryService service.FamilyHistoryService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *FamilyHistoryHandler {
	return &FamilyHistoryHandler{
		familyHistoryService: familyHistoryService,
		logger:               logger,
		timeout:              timeout,
	}
}

func (h *FamilyHistoryHandler) RegisterRoutes(router chi.Router) {
	router.Route("/family-history", func(r chi.Router) {
		r.Post("/", h.CreateFamilyHistory)
		r.Get("/patient/{patientID}", h.GetPatientFamilyHistory)
		r.Put("/{id}", h.UpdateFamilyHistory)
		r.Delete("/{id}", h.DeleteFamilyHistory)
	})
}

func (h *FamilyHistoryHandler) CreateFamilyHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateFamilyHistoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("relative", req.Relative)
	v.ValidateRequired("condition_name", req.ConditionName)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	history := pat_dto.ToDomainFamilyHistory(req)
	created, err := h.familyHistoryService.AddFamilyHistory(ctx, history)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToFamilyHistoryResponse(created))
}

func (h *FamilyHistoryHandler) GetPatientFamilyHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := uuid.Parse(chi.URLParam(r, "patientID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid patient ID format"})
		return
	}

	histories, err := h.familyHistoryService.GetPatientFamilyHistory(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.FamilyHistoryResponse, len(histories))
	for i, history := range histories {
		responses[i] = pat_dto.ToFamilyHistoryResponse(history)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.FamilyHistoriesListResponse{
		FamilyHistories: responses,
		Count:           len(responses),
	})
}

func (h *FamilyHistoryHandler) UpdateFamilyHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	historyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid history ID format"})
		return
	}

	var req pat_dto.UpdateFamilyHistoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("relative", req.Relative)
	v.ValidateRequired("condition_name", req.ConditionName)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	patientID, err := uuid.Parse(r.URL.Query().Get("patient_id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Patient ID is required"})
		return
	}

	histories, err := h.familyHistoryService.GetPatientFamilyHistory(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.FamilyHistoryResponse
	for _, history := range histories {
		if history.ID == historyID {
			resp := pat_dto.ToFamilyHistoryResponse(history)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{Error: "Family history not found"})
		return
	}

	existingDomain := pat_dto.ToDomainFamilyHistory(pat_dto.CreateFamilyHistoryRequest{
		PatientID:              existing.PatientID,
		Relative:               existing.Relative,
		RelativeAgeAtDiagnosis: existing.RelativeAgeAtDiagnosis,
		ConditionName:          existing.ConditionName,
		Notes:                  existing.Notes,
		IsAlive:                existing.IsAlive,
		CauseOfDeath:           existing.CauseOfDeath,
		AgeAtDeath:             existing.AgeAtDeath,
	})
	existingDomain.ID = existing.ID

	updated := pat_dto.UpdateToDomainFamilyHistory(existingDomain, req)
	if err := h.familyHistoryService.UpdateFamilyHistory(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	updatedHistories, err := h.familyHistoryService.GetPatientFamilyHistory(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, history := range updatedHistories {
		if history.ID == historyID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToFamilyHistoryResponse(history))
			return
		}
	}
}

func (h *FamilyHistoryHandler) DeleteFamilyHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	historyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid history ID format"})
		return
	}

	if err := h.familyHistoryService.DeleteFamilyHistory(ctx, historyID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{"message": "Family history deleted successfully"})
}
