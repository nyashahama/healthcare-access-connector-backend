package appointments

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	app_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type AppointmentHandler struct {
	appointmentService service.AppointmentService
	logger             *zerolog.Logger
	timeout            time.Duration
}

// NewAppointmentHandler creates a new appointment handler
func NewAppointmentHandler(
	appointmentService service.AppointmentService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *AppointmentHandler {
	return &AppointmentHandler{
		appointmentService: appointmentService,
		logger:             logger,
		timeout:            timeout,
	}
}

// RegisterRoutes registers appointment routes
func (h *AppointmentHandler) RegisterRoutes(router chi.Router) {
	router.Post("/", h.CreateAppointment)
	router.Get("/{id}", h.GetAppointmentByID)
	router.Get("/patient/{patientId}", h.GetAppointmentsByPatient)
	router.Get("/clinic/{clinicId}", h.GetAppointmentsByClinic)
	router.Get("/clinic/{clinicId}/date/{date}", h.GetAppointmentsByClinicAndDate)
	router.Get("/clinic/{clinicId}/today", h.GetTodayAppointments)
	router.Get("/clinic/{clinicId}/pending", h.GetPendingAppointments)
	router.Put("/{id}/reschedule", h.RescheduleAppointment)
	router.Put("/{id}/confirm", h.ConfirmAppointment)
	router.Put("/{id}/notes", h.UpdateAppointmentNotes)
	router.Put("/{id}/complete", h.CompleteAppointment)
	router.Put("/{id}/cancel", h.CancelAppointment)
	router.Put("/{id}/status", h.UpdateAppointmentStatus)
	router.Delete("/{id}", h.DeleteAppointment)
	router.Get("/patient/{patientId}/count", h.GetAppointmentCount)
}

// CreateAppointment handles creation of a new appointment
func (h *AppointmentHandler) CreateAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req app_dto.CreateAppointmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("clinic_id", req.ClinicID.String())
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("patient_name", req.PatientName)
	v.ValidateRequired("patient_phone", req.PatientPhone)
	v.ValidateRequired("reason_for_visit", req.ReasonForVisit)
	v.ValidateRequired("appointment_date", req.AppointmentDate.String())
	v.ValidateRequired("appointment_time", req.AppointmentTime.String())
	v.ValidateRequired("appointment_datetime", req.AppointmentDatetime.String())

	// Validate appointment is in the future
	if req.AppointmentDatetime.Before(time.Now()) {
		v.AddError("appointment_datetime", "Appointment must be in the future")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if claims.Role == "patient" && claims.UserID != req.PatientID {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot create an appointment for another user",
		})
		return
	}

	// Convert to domain model
	appointment := app_dto.ToDomainAppointment(req)

	// Create appointment
	created, err := h.appointmentService.BookAppointment(ctx, appointment)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, app_dto.ToAppointmentResponse(created))
}

// GetAppointmentByID retrieves an appointment by ID
func (h *AppointmentHandler) GetAppointmentByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	appointment, err := h.appointmentService.GetAppointmentByID(ctx, id, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(appointment))
}

// GetAppointmentsByPatient retrieves all appointments for a patient
func (h *AppointmentHandler) GetAppointmentsByPatient(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "patientId")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid patient ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if claims.Role == "patient" && claims.UserID != patientID {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot view another user's appointments",
		})
		return
	}

	appointmentList, err := h.appointmentService.GetAppointmentsByPatient(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := make([]app_dto.AppointmentResponse, len(appointmentList))
	for i, appointment := range appointmentList {
		response[i] = app_dto.ToAppointmentResponse(appointment)
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.GetAppointmentsResponse{
		Appointments: response,
		Count:        len(response),
		Total:        len(response),
	})
}

// GetAppointmentsByClinic retrieves all appointments for a clinic
func (h *AppointmentHandler) GetAppointmentsByClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinicId")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid clinic ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if !canReadClinicAppointments(claims) {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot view clinic appointments",
		})
		return
	}

	appointmentList, err := h.appointmentService.GetAppointmentsByClinic(ctx, clinicID, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := make([]app_dto.AppointmentResponse, len(appointmentList))
	for i, appointment := range appointmentList {
		response[i] = app_dto.ToAppointmentResponse(appointment)
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.GetAppointmentsResponse{
		Appointments: response,
		Count:        len(response),
		Total:        len(response),
	})
}

// GetAppointmentsByClinicAndDate retrieves appointments for a clinic on a specific date
func (h *AppointmentHandler) GetAppointmentsByClinicAndDate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinicId")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid clinic ID",
		})
		return
	}

	dateStr := chi.URLParam(r, "date")
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid date format. Use YYYY-MM-DD",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if !canReadClinicAppointments(claims) {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot view clinic appointments",
		})
		return
	}

	appointmentList, err := h.appointmentService.GetAppointmentsByClinicAndDate(ctx, clinicID, date, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := make([]app_dto.AppointmentResponse, len(appointmentList))
	for i, appointment := range appointmentList {
		response[i] = app_dto.ToAppointmentResponse(appointment)
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.GetAppointmentsResponse{
		Appointments: response,
		Count:        len(response),
		Total:        len(response),
	})
}

// GetTodayAppointments retrieves today's appointments for a clinic
func (h *AppointmentHandler) GetTodayAppointments(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinicId")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid clinic ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if !canReadClinicAppointments(claims) {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot view clinic appointments",
		})
		return
	}

	appointmentList, err := h.appointmentService.GetTodayAppointments(ctx, clinicID, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := make([]app_dto.AppointmentResponse, len(appointmentList))
	for i, appointment := range appointmentList {
		response[i] = app_dto.ToAppointmentResponse(appointment)
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.GetAppointmentsResponse{
		Appointments: response,
		Count:        len(response),
		Total:        len(response),
	})
}

// GetPendingAppointments retrieves all pending appointments for a clinic
func (h *AppointmentHandler) GetPendingAppointments(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinicId")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid clinic ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if !canReadClinicAppointments(claims) {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot view clinic appointments",
		})
		return
	}

	appointmentList, err := h.appointmentService.GetPendingAppointments(ctx, clinicID, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := make([]app_dto.AppointmentResponse, len(appointmentList))
	for i, appointment := range appointmentList {
		response[i] = app_dto.ToAppointmentResponse(appointment)
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.GetAppointmentsResponse{
		Appointments: response,
		Count:        len(response),
		Total:        len(response),
	})
}

// RescheduleAppointment handles rescheduling of an appointment
func (h *AppointmentHandler) RescheduleAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	var req app_dto.RescheduleAppointmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("appointment_date", req.AppointmentDate.String())
	v.ValidateRequired("appointment_time", req.AppointmentTime.String())
	v.ValidateRequired("appointment_datetime", req.AppointmentDatetime.String())

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	rescheduled, err := h.appointmentService.RescheduleAppointment(ctx, id, req.AppointmentDate, req.AppointmentTime, req.AppointmentDatetime, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(rescheduled))
}

// ConfirmAppointment handles confirmation of an appointment
func (h *AppointmentHandler) ConfirmAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	var req app_dto.ConfirmAppointmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}
	// Get user from context using middleware helper
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Get user ID from claims
	userID := claims.UserID
	// Validate input
	v := validator.New()
	// v.ValidateRequired("confirmed_by", string(userID))

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	confirmed, err := h.appointmentService.ConfirmAppointment(ctx, id, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(confirmed))
}

// UpdateAppointmentNotes handles updating appointment notes
func (h *AppointmentHandler) UpdateAppointmentNotes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	var req app_dto.UpdateAppointmentNotesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("notes", req.Notes)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	updated, err := h.appointmentService.UpdateAppointmentNotes(ctx, id, req.Notes, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(updated))
}

// CompleteAppointment handles marking an appointment as completed
func (h *AppointmentHandler) CompleteAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	completed, err := h.appointmentService.CompleteAppointment(ctx, id, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(completed))
}

// CancelAppointment handles cancellation of an appointment
func (h *AppointmentHandler) CancelAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	var req app_dto.CancelAppointmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("cancellation_reason", req.CancellationReason)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	cancelled, err := h.appointmentService.CancelAppointment(ctx, id, req.CancellationReason, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(cancelled))
}

// UpdateAppointmentStatus handles updating appointment status
func (h *AppointmentHandler) UpdateAppointmentStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	var req app_dto.UpdateAppointmentStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("status", req.Status)

	// Validate status value
	validStatuses := map[string]bool{
		string(appointments.StatusPending):   true,
		string(appointments.StatusConfirmed): true,
		string(appointments.StatusCancelled): true,
		string(appointments.StatusCompleted): true,
		string(appointments.StatusNoShow):    true,
	}
	if !validStatuses[req.Status] {
		v.AddError("status", "Invalid appointment status")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	updated, err := h.appointmentService.UpdateAppointmentStatus(ctx, id, appointments.AppointmentStatus(req.Status), claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, app_dto.ToAppointmentResponse(updated))
}

// DeleteAppointment handles deletion of a cancelled appointment
func (h *AppointmentHandler) DeleteAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid appointment ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = h.appointmentService.DeleteAppointment(ctx, id, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusNoContent, nil)
}

// GetAppointmentCount gets the total count of appointments for a patient
func (h *AppointmentHandler) GetAppointmentCount(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientIDStr := chi.URLParam(r, "patientId")
	patientID, err := uuid.Parse(patientIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, app_dto.ErrorResponse{
			Error: "Invalid patient ID",
		})
		return
	}

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, app_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}
	if claims.Role == "patient" && claims.UserID != patientID {
		handler.RespondJSON(w, http.StatusForbidden, app_dto.ErrorResponse{
			Error: "Cannot view another user's appointment count",
		})
		return
	}

	count, err := h.appointmentService.GetAppointmentCount(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"patient_id": patientID,
		"count":      count,
	})
}

func canReadClinicAppointments(claims *service.TokenClaims) bool {
	if claims == nil {
		return false
	}
	switch claims.Role {
	case "provider_staff", "doctor", "clinic_admin", "system_admin":
		return true
	default:
		return false
	}
}
