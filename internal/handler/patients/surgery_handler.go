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

type SurgeryHandler struct {
	surgeryService service.SurgeryService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewSurgeryHandler creates a new surgery handler
func NewSurgeryHandler(
	surgeryService service.SurgeryService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *SurgeryHandler {
	return &SurgeryHandler{
		surgeryService: surgeryService,
		logger:         logger,
		timeout:        timeout,
	}
}

// RegisterRoutes registers surgery routes
func (h *SurgeryHandler) RegisterRoutes(router chi.Router) {
	router.Route("/surgeries", func(r chi.Router) {
		r.Post("/", h.CreateSurgery)
		r.Get("/patient/{patientID}", h.GetPatientSurgeries)
		r.Get("/patient/{patientID}/recent", h.GetRecentSurgeries)
		r.Put("/{id}", h.UpdateSurgery)
		r.Delete("/{id}", h.DeleteSurgery)
	})
}

func (h *SurgeryHandler) CreateSurgery(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateSurgeryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("procedure_name", req.ProcedureName)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Create surgery
	surgery := pat_dto.ToDomainSurgery(req)
	created, err := h.surgeryService.AddPatientSurgery(ctx, surgery)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToSurgeryResponse(created))
}

func (h *SurgeryHandler) GetPatientSurgeries(w http.ResponseWriter, r *http.Request) {
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

	// Get surgeries
	surgeries, err := h.surgeryService.GetPatientSurgeries(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.SurgeryResponse, len(surgeries))
	for i, surgery := range surgeries {
		responses[i] = pat_dto.ToSurgeryResponse(surgery)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.SurgeriesListResponse{
		Surgeries: responses,
		Count:     len(responses),
	})
}

func (h *SurgeryHandler) GetRecentSurgeries(w http.ResponseWriter, r *http.Request) {
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

	// Get recent surgeries
	surgeries, err := h.surgeryService.GetRecentSurgeries(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	responses := make([]pat_dto.SurgeryResponse, len(surgeries))
	for i, surgery := range surgeries {
		responses[i] = pat_dto.ToSurgeryResponse(surgery)
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.SurgeriesListResponse{
		Surgeries: responses,
		Count:     len(responses),
	})
}

func (h *SurgeryHandler) UpdateSurgery(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	surgeryIDStr := chi.URLParam(r, "id")
	surgeryID, err := uuid.Parse(surgeryIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid surgery ID format",
		})
		return
	}

	var req pat_dto.UpdateSurgeryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("procedure_name", req.ProcedureName)

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

	// Get existing surgeries to find the one to update
	surgeries, err := h.surgeryService.GetPatientSurgeries(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	var existing *pat_dto.SurgeryResponse
	for _, surgery := range surgeries {
		if surgery.ID == surgeryID {
			resp := pat_dto.ToSurgeryResponse(surgery)
			existing = &resp
			break
		}
	}

	if existing == nil {
		handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{
			Error: "Surgery not found",
		})
		return
	}

	// Convert existing response back to domain
	existingDomain := pat_dto.ToDomainSurgery(pat_dto.CreateSurgeryRequest{
		PatientID:      existing.PatientID,
		ProcedureName:  existing.ProcedureName,
		ProcedureDate:  existing.ProcedureDate,
		HospitalName:   existing.HospitalName,
		SurgeonName:    existing.SurgeonName,
		AnesthesiaType: existing.AnesthesiaType,
		Complications:  existing.Complications,
		RecoveryNotes:  existing.RecoveryNotes,
		Outcome:        existing.Outcome,
	})
	existingDomain.ID = existing.ID

	// Update surgery
	updated := pat_dto.UpdateToDomainSurgery(existingDomain, req)
	if err := h.surgeryService.UpdatePatientSurgery(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated surgery
	updatedSurgeries, err := h.surgeryService.GetPatientSurgeries(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	for _, surgery := range updatedSurgeries {
		if surgery.ID == surgeryID {
			handler.RespondJSON(w, http.StatusOK, pat_dto.ToSurgeryResponse(surgery))
			return
		}
	}

	handler.RespondJSON(w, http.StatusNotFound, pat_dto.ErrorResponse{
		Error: "Surgery not found after update",
	})
}

func (h *SurgeryHandler) DeleteSurgery(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	surgeryIDStr := chi.URLParam(r, "id")
	surgeryID, err := uuid.Parse(surgeryIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid surgery ID format",
		})
		return
	}

	if err := h.surgeryService.DeletePatientSurgery(ctx, surgeryID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Surgery deleted successfully",
	})
}
