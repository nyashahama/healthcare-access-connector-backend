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

type MedicalInfoHandler struct {
	medicalInfoService service.MedicalInfoService
	logger             *zerolog.Logger
	timeout            time.Duration
}

// NewMedicalInfoHandler creates a new medical info handler
func NewMedicalInfoHandler(
	medicalInfoService service.MedicalInfoService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *MedicalInfoHandler {
	return &MedicalInfoHandler{
		medicalInfoService: medicalInfoService,
		logger:             logger,
		timeout:            timeout,
	}
}

// RegisterRoutes registers medical info routes
func (h *MedicalInfoHandler) RegisterRoutes(router chi.Router) {
	router.Route("/medical-info", func(r chi.Router) {
		r.Post("/", h.CreateMedicalInfo)
		r.Get("/{id}", h.GetMedicalInfoByID)
		r.Get("/patient/{patientID}", h.GetMedicalInfoByPatientID)
		r.Put("/patient/{patientID}", h.UpdateMedicalInfo)
		r.Delete("/patient/{patientID}", h.DeleteMedicalInfo)
	})
}

func (h *MedicalInfoHandler) CreateMedicalInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req pat_dto.CreateMedicalInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Create medical info
	medicalInfo := pat_dto.ToDomainMedicalInfo(req)
	created, err := h.medicalInfoService.CreateMedicalInfo(ctx, medicalInfo)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, pat_dto.ToMedicalInfoResponse(created))
}

func (h *MedicalInfoHandler) GetMedicalInfoByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	medicalInfoIDStr := chi.URLParam(r, "id")
	medicalInfoID, err := uuid.Parse(medicalInfoIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid medical info ID format",
		})
		return
	}

	// Get medical info
	medicalInfo, err := h.medicalInfoService.GetMedicalInfoByID(ctx, medicalInfoID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToMedicalInfoResponse(medicalInfo))
}

func (h *MedicalInfoHandler) GetMedicalInfoByPatientID(w http.ResponseWriter, r *http.Request) {
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

	// Get medical info
	medicalInfo, err := h.medicalInfoService.GetMedicalInfoByPatientID(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToMedicalInfoResponse(medicalInfo))
}

func (h *MedicalInfoHandler) UpdateMedicalInfo(w http.ResponseWriter, r *http.Request) {
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

	var req pat_dto.UpdateMedicalInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, pat_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Get existing medical info
	existing, err := h.medicalInfoService.GetMedicalInfoByPatientID(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Update medical info
	updated := pat_dto.UpdateToDomainMedicalInfo(existing, req)
	if err := h.medicalInfoService.UpdateMedicalInfo(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated medical info
	updatedInfo, err := h.medicalInfoService.GetMedicalInfoByPatientID(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, pat_dto.ToMedicalInfoResponse(updatedInfo))
}

func (h *MedicalInfoHandler) DeleteMedicalInfo(w http.ResponseWriter, r *http.Request) {
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

	if err := h.medicalInfoService.DeleteMedicalInfoByPatientID(ctx, patientID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Medical info deleted successfully",
	})
}
