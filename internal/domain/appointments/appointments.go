package appointments

import (
	"time"

	"github.com/google/uuid"
)

type AppointmentStatus string

const (
	StatusPending   AppointmentStatus = "pending"
	StatusConfirmed AppointmentStatus = "confirmed"
	StatusCancelled AppointmentStatus = "cancelled"
	StatusCompleted AppointmentStatus = "completed"
	StatusNoShow    AppointmentStatus = "no_show"
)

type Appointment struct {
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
	Status              AppointmentStatus      `json:"status"`
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
