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

type DependentHealthRecordHandler struct {
	dependentHealthService service.DependentHealthRecordService
	logger                 *zerolog.Logger
	timeout                time.Duration
}

func NewDependentHealthRecordHandler(dependentHealthService service.DependentHealthRecordService, logger *zerolog.Logger, timeout time.Duration) *DependentHealthRecordHandler {
	return &DependentHealthRecordHandler{dependentHealthService: dependentHealthService, logger: logger, timeout: timeout}
}

func (h *DependentHealthRecordHandler) RegisterRoutes(router chi.Router) {
	router.Route("/dependent-health-records", func(r chi.Router) {
		r.Post("/", h.CreateHealthRecord)
		r.Get("/dependent/{dependentID}", h.GetDependentHealthRecords)
		r.Get("/dependent/{dependentID}/growth", h.GetGrowthRecords)
		r.Put("/{id}", h.UpdateHealthRecord)
		r.Delete("/{id}", h.DeleteHealthRecord)
	})
}

func (h *DependentHealthRecordHandler) CreateHealthRecord(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateDependentHealthRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("dependent_id", req.DependentID.String())

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	record := pat_dto.ToDomainDependentHealthRecord(req)
	created, err := h.dependentHealthService.AddDependentHealthRecord(ctx, record)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToDependentHealthRecordResponse(created))
}

func (h *DependentHealthRecordHandler) GetDependentHealthRecords(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	dependentID, err := uuid.Parse(chi.URLParam(r, "dependentID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid dependent ID format"})
		return
	}

	records, err := h.dependentHealthService.GetDependentHealthRecords(ctx, dependentID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.DependentHealthRecordResponse, len(records))
	for i, record := range records {
		responses[i] = pat_dto.ToDependentHealthRecordResponse(record)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.DependentHealthRecordsListResponse{HealthRecords: responses, Count: len(responses)})
}

func (h *DependentHealthRecordHandler) GetGrowthRecords(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	dependentID, err := uuid.Parse(chi.URLParam(r, "dependentID"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid dependent ID format"})
		return
	}

	records, err := h.dependentHealthService.GetGrowthRecords(ctx, dependentID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]pat_dto.DependentHealthRecordResponse, len(records))
	for i, record := range records {
		responses[i] = pat_dto.ToDependentHealthRecordResponse(record)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.DependentHealthRecordsListResponse{HealthRecords: responses, Count: len(responses)})
}

func (h *DependentHealthRecordHandler) UpdateHealthRecord(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	recordID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid record ID format"})
		return
	}

	var req pat_dto.UpdateDependentHealthRecordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	dependentID, err := uuid.Parse(r.URL.Query().Get("dependent_id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Dependent ID is required"})
		return
	}

	records, err := h.dependentHealthService.GetDependentHealthRecords(ctx, dependentID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.DependentHealthRecordResponse
	for _, record := range records {
		if record.ID == recordID {
			resp := pat_dto.ToDependentHealthRecordResponse(record)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{Error: "Health record not found"})
		return
	}

	existingDomain := pat_dto.ToDomainDependentHealthRecord(pat_dto.CreateDependentHealthRecordRequest{
		DependentID:         existing.DependentID,
		RecordType:          existing.RecordType,
		RecordDate:          existing.RecordDate,
		WeightKg:            existing.WeightKg,
		HeightCm:            existing.HeightCm,
		HeadCircumferenceCm: existing.HeadCircumferenceCm,
		TemperatureC:        existing.TemperatureC,
		Notes:               existing.Notes,
		ProviderName:        existing.ProviderName,
		ClinicName:          existing.ClinicName,
		NextAppointmentDate: existing.NextAppointmentDate,
		Documents:           existing.Documents,
	})
	existingDomain.ID = existing.ID

	updated := pat_dto.UpdateToDomainDependentHealthRecord(existingDomain, req)
	if err := h.dependentHealthService.UpdateDependentHealthRecord(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	updatedRecords, err := h.dependentHealthService.GetDependentHealthRecords(ctx, dependentID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, record := range updatedRecords {
		if record.ID == recordID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToDependentHealthRecordResponse(record))
			return
		}
	}
}

func (h *DependentHealthRecordHandler) DeleteHealthRecord(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	recordID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{Error: "Invalid record ID format"})
		return
	}

	if err := h.dependentHealthService.DeleteDependentHealthRecord(ctx, recordID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{"message": "Health record deleted successfully"})
}
