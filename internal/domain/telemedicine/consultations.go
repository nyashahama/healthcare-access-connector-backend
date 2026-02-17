package telemedicine

import (
	"time"

	"github.com/google/uuid"
)

// ConsultationStatus represents the full lifecycle of a telemedicine consultation.
type ConsultationStatus string

const (
	ConsultationStatusPendingAcceptance ConsultationStatus = "pending_acceptance"
	ConsultationStatusAccepted          ConsultationStatus = "accepted"
	ConsultationStatusInProgress        ConsultationStatus = "in_progress"
	ConsultationStatusCompleted         ConsultationStatus = "completed"
	ConsultationStatusCancelled         ConsultationStatus = "cancelled"
	ConsultationStatusNoShow            ConsultationStatus = "no_show"
	ConsultationStatusEscalated         ConsultationStatus = "escalated"
	ConsultationStatusDeclined          ConsultationStatus = "declined"
)

// ConsultationChannel represents the communication medium.
type ConsultationChannel string

const (
	ChannelChat  ConsultationChannel = "chat"
	ChannelVideo ConsultationChannel = "video"
	ChannelPhone ConsultationChannel = "phone"
)

// ConsultationEndReason captures why a consultation closed.
type ConsultationEndReason string

const (
	EndReasonCompleted ConsultationEndReason = "completed"
	EndReasonNoShow    ConsultationEndReason = "no_show"
	EndReasonCancelled ConsultationEndReason = "cancelled"
	EndReasonEscalated ConsultationEndReason = "escalated"
	EndReasonDeclined  ConsultationEndReason = "declined"
)

// PaymentStatus represents the billing state of a consultation.
type PaymentStatus string

const (
	PaymentStatusPending PaymentStatus = "pending"
	PaymentStatusPaid    PaymentStatus = "paid"
	PaymentStatusWaived  PaymentStatus = "waived"
	PaymentStatusFailed  PaymentStatus = "failed"
)

// Consultation is the core domain model for a telemedicine session.
// Every consultation must originate from a completed symptom_checker_session.
type Consultation struct {
	ID                uuid.UUID  `json:"id"`
	SymptomSessionID  uuid.UUID  `json:"symptom_session_id"`
	PatientID         uuid.UUID  `json:"patient_id"`
	ProviderStaffID   *uuid.UUID `json:"provider_staff_id,omitempty"`
	ClinicID          *uuid.UUID `json:"clinic_id,omitempty"`

	Channel           ConsultationChannel `json:"channel"`
	TriageLevelAtStart *string            `json:"triage_level_at_start,omitempty"`

	// Lifecycle timestamps
	RequestedAt *time.Time `json:"requested_at,omitempty"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	EndedAt     *time.Time `json:"ended_at,omitempty"`

	DurationSeconds *int `json:"duration_seconds,omitempty"`

	// Status & close metadata
	Status    ConsultationStatus     `json:"status"`
	EndedBy   *uuid.UUID             `json:"ended_by,omitempty"`
	EndReason *ConsultationEndReason `json:"end_reason,omitempty"`

	// Billing
	ConsultationFee  *float64      `json:"consultation_fee,omitempty"`
	FeeCurrency      string        `json:"fee_currency"`
	PaymentStatus    PaymentStatus `json:"payment_status"`
	PaymentReference *string       `json:"payment_reference,omitempty"`

	// Post-consultation rating
	PatientRating   *int       `json:"patient_rating,omitempty"` // 1–5
	PatientFeedback *string    `json:"patient_feedback,omitempty"`
	RatedAt         *time.Time `json:"rated_at,omitempty"`

	// Optional follow-up appointment linked during the same flow
	FollowUpAppointmentID *uuid.UUID `json:"follow_up_appointment_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ConsultationWithDetails is the rich view used to hydrate a chat screen for
// both patient and provider. It joins consultation → symptom session → patient
// profile → clinic_staff.
type ConsultationWithDetails struct {
	// All core Consultation fields
	Consultation

	// From symptom_checker_sessions
	ChiefComplaint     string   `json:"chief_complaint"`
	AISummary          *string  `json:"ai_summary,omitempty"`
	SessionTriageLevel *string  `json:"session_triage_level,omitempty"`
	SymptomsReported   []string `json:"symptoms_reported,omitempty"`

	// From patient_profiles
	PatientFirstName               string  `json:"patient_first_name"`
	PatientLastName                string  `json:"patient_last_name"`
	PreferredCommunicationMethod   *string `json:"preferred_communication_method,omitempty"`

	// From clinic_staff (left-joined — nil until a provider accepts)
	ProviderFirstName      *string `json:"provider_first_name,omitempty"`
	ProviderLastName       *string `json:"provider_last_name,omitempty"`
	ProviderSpecialization *string `json:"provider_specialization,omitempty"`
	ProviderTitle          *string `json:"provider_title,omitempty"`
}

// PatientConsultationSummary is the patient-facing history list projection.
type PatientConsultationSummary struct {
	ID                  uuid.UUID          `json:"id"`
	Status              ConsultationStatus `json:"status"`
	Channel             ConsultationChannel `json:"channel"`
	TriageLevelAtStart  *string            `json:"triage_level_at_start,omitempty"`
	RequestedAt         *time.Time         `json:"requested_at,omitempty"`
	StartedAt           *time.Time         `json:"started_at,omitempty"`
	EndedAt             *time.Time         `json:"ended_at,omitempty"`
	DurationSeconds     *int               `json:"duration_seconds,omitempty"`
	ConsultationFee     *float64           `json:"consultation_fee,omitempty"`
	PaymentStatus       PaymentStatus      `json:"payment_status"`
	PatientRating       *int               `json:"patient_rating,omitempty"`

	// Joined fields
	ChiefComplaint         string  `json:"chief_complaint"`
	ProviderFirstName      *string `json:"provider_first_name,omitempty"`
	ProviderLastName       *string `json:"provider_last_name,omitempty"`
	ProviderSpecialization *string `json:"provider_specialization,omitempty"`
}

// ActiveConsultationCheck is the minimal projection used to prevent duplicate
// open consultations for a patient.
type ActiveConsultationCheck struct {
	ID              uuid.UUID          `json:"id"`
	Status          ConsultationStatus `json:"status"`
	ProviderStaffID *uuid.UUID         `json:"provider_staff_id,omitempty"`
	Channel         ConsultationChannel `json:"channel"`
}

// ProviderActiveConsultation is the provider dashboard view, showing each open
// consultation enriched with patient identity, symptom context, and an unread
// message count. Ordered by triage priority.
type ProviderActiveConsultation struct {
	ID                 uuid.UUID          `json:"id"`
	Status             ConsultationStatus `json:"status"`
	TriageLevelAtStart *string            `json:"triage_level_at_start,omitempty"`
	RequestedAt        *time.Time         `json:"requested_at,omitempty"`
	StartedAt          *time.Time         `json:"started_at,omitempty"`
	Channel            ConsultationChannel `json:"channel"`

	// Patient identity (from patient_profiles)
	PatientFirstName               string  `json:"patient_first_name"`
	PatientLastName                string  `json:"patient_last_name"`
	PreferredCommunicationMethod   *string `json:"preferred_communication_method,omitempty"`
	RequiresInterpreter            bool    `json:"requires_interpreter"`

	// Symptom context (from symptom_checker_sessions)
	ChiefComplaint string  `json:"chief_complaint"`
	AISummary      *string `json:"ai_summary,omitempty"`
	SeverityScore  *int    `json:"severity_score,omitempty"`

	// Aggregated from consultation_messages
	UnreadMessages int64 `json:"unread_messages"`
}

// WaitingRoomEntry is the provider-facing view of a pending consultation in
// the waiting room — no provider has accepted it yet.
type WaitingRoomEntry struct {
	ID                 uuid.UUID           `json:"id"`
	TriageLevelAtStart *string             `json:"triage_level_at_start,omitempty"`
	RequestedAt        *time.Time          `json:"requested_at,omitempty"`
	Channel            ConsultationChannel `json:"channel"`
	ConsultationFee    *float64            `json:"consultation_fee,omitempty"`

	// Patient identity
	PatientFirstName string `json:"patient_first_name"`
	PatientLastName  string `json:"patient_last_name"`

	// Symptom context
	ChiefComplaint string  `json:"chief_complaint"`
	SeverityScore  *int    `json:"severity_score,omitempty"`
	AISummary      *string `json:"ai_summary,omitempty"`
}

// ProviderConsultationHistoryEntry is the provider history list projection,
// covering closed consultations (completed, no_show, escalated, cancelled).
type ProviderConsultationHistoryEntry struct {
	ID              uuid.UUID              `json:"id"`
	Status          ConsultationStatus     `json:"status"`
	Channel         ConsultationChannel    `json:"channel"`
	RequestedAt     *time.Time             `json:"requested_at,omitempty"`
	EndedAt         *time.Time             `json:"ended_at,omitempty"`
	DurationSeconds *int                   `json:"duration_seconds,omitempty"`
	ConsultationFee *float64               `json:"consultation_fee,omitempty"`
	PaymentStatus   PaymentStatus          `json:"payment_status"`
	PatientRating   *int                   `json:"patient_rating,omitempty"`
	EndReason       *ConsultationEndReason `json:"end_reason,omitempty"`

	// Joined fields
	PatientFirstName string `json:"patient_first_name"`
	PatientLastName  string `json:"patient_last_name"`
	ChiefComplaint   string `json:"chief_complaint"`
}