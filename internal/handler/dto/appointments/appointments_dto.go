package appointments

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
)

// CreateAppointmentRequest represents a request to create an appointment
type CreateAppointmentRequest struct {
	ClinicID            uuid.UUID              `json:"clinic_id"`
	PatientID           uuid.UUID              `json:"patient_id"`
	AppointmentDate     time.Time              `json:"appointment_date"`
	AppointmentTime     time.Time              `json:"appointment_time"`
	AppointmentDatetime time.Time              `json:"appointment_datetime"`
	PatientName         string                 `json:"patient_name"`
	PatientPhone        string                 `json:"patient_phone"`
	PatientEmail        *string                `json:"patient_email,omitempty"`
	ReasonForVisit      string                 `json:"reason_for_visit"`
	Notes               *string                `json:"notes,omitempty"`
	ReminderPreferences map[string]interface{} `json:"reminder_preferences,omitempty"`
}

// UpdateAppointmentRequest represents a request to update an appointment
type UpdateAppointmentRequest struct {
	AppointmentDate     time.Time              `json:"appointment_date"`
	AppointmentTime     time.Time              `json:"appointment_time"`
	AppointmentDatetime time.Time              `json:"appointment_datetime"`
	PatientName         string                 `json:"patient_name"`
	PatientPhone        string                 `json:"patient_phone"`
	PatientEmail        *string                `json:"patient_email,omitempty"`
	ReasonForVisit      string                 `json:"reason_for_visit"`
	Notes               *string                `json:"notes,omitempty"`
	ReminderPreferences map[string]interface{} `json:"reminder_preferences,omitempty"`
}

// RescheduleAppointmentRequest represents a request to reschedule an appointment
type RescheduleAppointmentRequest struct {
	AppointmentDate     time.Time `json:"appointment_date"`
	AppointmentTime     time.Time `json:"appointment_time"`
	AppointmentDatetime time.Time `json:"appointment_datetime"`
}

// CancelAppointmentRequest represents a request to cancel an appointment
type CancelAppointmentRequest struct {
	CancellationReason string    `json:"cancellation_reason"`
	CancelledBy        uuid.UUID `json:"cancelled_by"`
}

// ConfirmAppointmentRequest represents a request to confirm an appointment
type ConfirmAppointmentRequest struct {
	ConfirmedBy uuid.UUID `json:"confirmed_by"`
}

// UpdateAppointmentNotesRequest represents a request to update appointment notes
type UpdateAppointmentNotesRequest struct {
	Notes string `json:"notes"`
}

// UpdateAppointmentStatusRequest represents a request to update appointment status
type UpdateAppointmentStatusRequest struct {
	Status string `json:"status"`
}

// AppointmentResponse represents an appointment in responses
type AppointmentResponse struct {
	ID                  uuid.UUID              `json:"id"`
	ClinicID            uuid.UUID              `json:"clinic_id"`
	PatientID           uuid.UUID              `json:"patient_id"`
	AppointmentDate     time.Time              `json:"appointment_date"`
	AppointmentTime     time.Time              `json:"appointment_time"`
	AppointmentDatetime time.Time              `json:"appointment_datetime"`
	PatientName         string                 `json:"patient_name"`
	PatientPhone        string                 `json:"patient_phone"`
	PatientEmail        *string                `json:"patient_email,omitempty"`
	ReasonForVisit      string                 `json:"reason_for_visit"`
	Notes               *string                `json:"notes,omitempty"`
	Status              string                 `json:"status"`
	CancellationReason  *string                `json:"cancellation_reason,omitempty"`
	CancelledBy         *uuid.UUID             `json:"cancelled_by,omitempty"`
	CancelledAt         *time.Time             `json:"cancelled_at,omitempty"`
	ConfirmedBy         *uuid.UUID             `json:"confirmed_by,omitempty"`
	ConfirmedAt         *time.Time             `json:"confirmed_at,omitempty"`
	ReminderPreferences map[string]interface{} `json:"reminder_preferences,omitempty"`
	ReminderSent        map[string]interface{} `json:"reminder_sent,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// GetAppointmentsRequest represents a request to get appointments with filters
type GetAppointmentsRequest struct {
	ClinicID  *uuid.UUID `json:"clinic_id,omitempty"`
	PatientID *uuid.UUID `json:"patient_id,omitempty"`
	Date      *time.Time `json:"date,omitempty"`
	Status    *string    `json:"status,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// GetAppointmentsResponse represents a response containing multiple appointments
type GetAppointmentsResponse struct {
	Appointments []AppointmentResponse `json:"appointments"`
	Count        int                   `json:"count"`
	Total        int                   `json:"total"`
	Limit        int                   `json:"limit"`
	Offset       int                   `json:"offset"`
}

// SchedulingConflictResponse represents a scheduling conflict
type SchedulingConflictResponse struct {
	HasConflict   bool       `json:"has_conflict"`
	ConflictingID *uuid.UUID `json:"conflicting_id,omitempty"`
	PatientName   *string    `json:"patient_name,omitempty"`
	Time          *time.Time `json:"time,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

// ToAppointmentResponse converts domain Appointment to response DTO
func ToAppointmentResponse(appointment appointments.Appointment) AppointmentResponse {
	return AppointmentResponse{
		ID:                  appointment.ID,
		ClinicID:            appointment.ClinicID,
		PatientID:           appointment.PatientID,
		AppointmentDate:     appointment.AppointmentDate,
		AppointmentTime:     appointment.AppointmentTime,
		AppointmentDatetime: appointment.AppointmentDatetime,
		PatientName:         appointment.PatientName,
		PatientPhone:        appointment.PatientPhone,
		PatientEmail:        appointment.PatientEmail,
		ReasonForVisit:      appointment.ReasonForVisit,
		Notes:               appointment.Notes,
		Status:              string(appointment.Status),
		CancellationReason:  appointment.CancellationReason,
		CancelledBy:         appointment.CancelledBy,
		CancelledAt:         appointment.CancelledAt,
		ConfirmedBy:         appointment.ConfirmedBy,
		ConfirmedAt:         appointment.ConfirmedAt,
		ReminderPreferences: appointment.ReminderPreferences,
		ReminderSent:        appointment.ReminderSent,
		CreatedAt:           appointment.CreatedAt,
		UpdatedAt:           appointment.UpdatedAt,
	}
}

// ToDomainAppointment converts request DTO to domain model
func ToDomainAppointment(req CreateAppointmentRequest) appointments.Appointment {
	return appointments.Appointment{
		ClinicID:            req.ClinicID,
		PatientID:           req.PatientID,
		AppointmentDate:     req.AppointmentDate,
		AppointmentTime:     req.AppointmentTime,
		AppointmentDatetime: req.AppointmentDatetime,
		PatientName:         req.PatientName,
		PatientPhone:        req.PatientPhone,
		PatientEmail:        req.PatientEmail,
		ReasonForVisit:      req.ReasonForVisit,
		Notes:               req.Notes,
		ReminderPreferences: req.ReminderPreferences,
		Status:              appointments.StatusPending, // Default status
	}
}

// UpdateToDomainAppointment updates existing domain model with request data
func UpdateToDomainAppointment(existing appointments.Appointment, req UpdateAppointmentRequest) appointments.Appointment {
	existing.AppointmentDate = req.AppointmentDate
	existing.AppointmentTime = req.AppointmentTime
	existing.AppointmentDatetime = req.AppointmentDatetime
	existing.PatientName = req.PatientName
	existing.PatientPhone = req.PatientPhone
	existing.PatientEmail = req.PatientEmail
	existing.ReasonForVisit = req.ReasonForVisit
	existing.Notes = req.Notes
	if req.ReminderPreferences != nil {
		existing.ReminderPreferences = req.ReminderPreferences
	}
	return existing
}
