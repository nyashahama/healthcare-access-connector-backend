package appointments

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	app_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/appointments"
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
	router.Route("/appointments", func(r chi.Router) {
		r.Post("/", h.CreateAppointment)
		// r.Get("/", h.GetAppointments)
		// r.Get("/today", h.GetTodayAppointments)
		// r.Get("/pending", h.GetPendingAppointments)
		//
		// r.Route("/clinic/{clinicID}", func(r chi.Router) {
		// 	r.Get("/", h.GetAppointmentsByClinic)
		// 	r.Get("/date/{date}", h.GetAppointmentsByClinicAndDate)
		// })
		//
		// r.Route("/patient/{patientID}", func(r chi.Router) {
		// 	r.Get("/", h.GetAppointmentsByPatient)
		// 	r.Get("/upcoming", h.GetUpcomingAppointments)
		// 	r.Get("/count", h.GetAppointmentCount)
		// })
		//
		// r.Route("/{id}", func(r chi.Router) {
		// 	r.Get("/", h.GetAppointment)
		// 	r.Put("/", h.UpdateAppointment)
		// 	r.Delete("/", h.DeleteAppointment)
		// 	r.Post("/reschedule", h.RescheduleAppointment)
		// 	r.Post("/cancel", h.CancelAppointment)
		// 	r.Post("/confirm", h.ConfirmAppointment)
		// 	r.Post("/complete", h.CompleteAppointment)
		// 	r.Put("/notes", h.UpdateAppointmentNotes)
		// 	r.Put("/status", h.UpdateAppointmentStatus)
		// })
		//
		// r.Post("/check-conflict", h.CheckSchedulingConflict)
	})
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
