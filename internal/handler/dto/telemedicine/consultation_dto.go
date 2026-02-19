package telemedicine

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
)

// ─── Request DTOs ──────────────────────────────────────────────────────────────

// RequestConsultationRequest is the patient-facing payload for creating a new
// consultation from a completed symptom checker session.
type RequestConsultationRequest struct {
	PatientID        uuid.UUID                        `json:"patient_id"`
	SymptomSessionID uuid.UUID                        `json:"symptom_session_id"`
	Channel          telemedicine.ConsultationChannel `json:"channel"`
	ConsultationFee  *float64                         `json:"consultation_fee,omitempty"`
	FeeCurrency      string                           `json:"fee_currency,omitempty"`
	ProviderStaffID  *uuid.UUID                       `json:"provider_staff_id,omitempty"`
	ClinicID         *uuid.UUID                       `json:"clinic_id,omitempty"`
}

// AcceptConsultationRequest carries the provider's staff ID used to accept
// a pending consultation from the waiting room.
type AcceptConsultationRequest struct {
	ProviderStaffID uuid.UUID `json:"provider_staff_id"`
}

// StartConsultationRequest is sent when a provider moves a consultation from
// accepted → in_progress.
type StartConsultationRequest struct {
	ProviderStaffID uuid.UUID `json:"provider_staff_id"`
}

// EndConsultationRequest carries the actor and the reason used to close a
// consultation.
type EndConsultationRequest struct {
	EndedBy   uuid.UUID                          `json:"ended_by"`
	EndReason telemedicine.ConsultationEndReason `json:"end_reason"`
}

// CancelConsultationRequest is the patient-facing payload for cancelling a
// pending or accepted consultation.
type CancelConsultationRequest struct {
	PatientID uuid.UUID `json:"patient_id"`
}

// EscalateConsultationRequest is used when a provider escalates a consultation.
type EscalateConsultationRequest struct {
	ProviderStaffID uuid.UUID `json:"provider_staff_id"`
}

// SubmitRatingRequest is the patient-facing payload for rating a completed
// consultation.
type SubmitRatingRequest struct {
	Rating   int     `json:"rating"`             // 1–5
	Feedback *string `json:"feedback,omitempty"` // optional free-text
}

// UpdatePaymentStatusRequest is used by billing services to record payment
// outcomes.
type UpdatePaymentStatusRequest struct {
	Status    telemedicine.PaymentStatus `json:"status"`
	Reference *string                    `json:"reference,omitempty"`
}

// UpdateConsultationChannelRequest is used to switch the communication channel
// mid-consultation (e.g. chat → video).
type UpdateConsultationChannelRequest struct {
	Channel telemedicine.ConsultationChannel `json:"channel"`
}

// LinkFollowUpAppointmentRequest associates a follow-up appointment with a
// closed consultation.
type LinkFollowUpAppointmentRequest struct {
	AppointmentID uuid.UUID `json:"appointment_id"`
}

// GetPatientConsultationsRequest carries pagination params for the patient
// history endpoint.
type GetPatientConsultationsRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// GetProviderConsultationHistoryRequest carries pagination params for the
// provider history endpoint.
type GetProviderConsultationHistoryRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ─── Response DTOs ─────────────────────────────────────────────────────────────

// ConsultationResponse is the full consultation response returned after create
// or individual GET.
type ConsultationResponse struct {
	ID                    uuid.UUID                           `json:"id"`
	SymptomSessionID      uuid.UUID                           `json:"symptom_session_id"`
	PatientID             uuid.UUID                           `json:"patient_id"`
	ProviderStaffID       *uuid.UUID                          `json:"provider_staff_id,omitempty"`
	ClinicID              *uuid.UUID                          `json:"clinic_id,omitempty"`
	Channel               telemedicine.ConsultationChannel    `json:"channel"`
	TriageLevelAtStart    *string                             `json:"triage_level_at_start,omitempty"`
	RequestedAt           *time.Time                          `json:"requested_at,omitempty"`
	AcceptedAt            *time.Time                          `json:"accepted_at,omitempty"`
	StartedAt             *time.Time                          `json:"started_at,omitempty"`
	EndedAt               *time.Time                          `json:"ended_at,omitempty"`
	DurationSeconds       *int                                `json:"duration_seconds,omitempty"`
	Status                telemedicine.ConsultationStatus     `json:"status"`
	EndedBy               *uuid.UUID                          `json:"ended_by,omitempty"`
	EndReason             *telemedicine.ConsultationEndReason `json:"end_reason,omitempty"`
	ConsultationFee       *float64                            `json:"consultation_fee,omitempty"`
	FeeCurrency           string                              `json:"fee_currency"`
	PaymentStatus         telemedicine.PaymentStatus          `json:"payment_status"`
	PaymentReference      *string                             `json:"payment_reference,omitempty"`
	PatientRating         *int                                `json:"patient_rating,omitempty"`
	PatientFeedback       *string                             `json:"patient_feedback,omitempty"`
	RatedAt               *time.Time                          `json:"rated_at,omitempty"`
	FollowUpAppointmentID *uuid.UUID                          `json:"follow_up_appointment_id,omitempty"`
	CreatedAt             time.Time                           `json:"created_at"`
	UpdatedAt             time.Time                           `json:"updated_at"`
}

// ConsultationWithDetailsResponse is the rich chat-screen hydrated view.
type ConsultationWithDetailsResponse struct {
	ConsultationResponse

	// From symptom_checker_sessions
	ChiefComplaint     string   `json:"chief_complaint"`
	AISummary          *string  `json:"ai_summary,omitempty"`
	SessionTriageLevel *string  `json:"session_triage_level,omitempty"`
	SymptomsReported   []string `json:"symptoms_reported,omitempty"`

	// From patient_profiles
	PatientFirstName             string  `json:"patient_first_name"`
	PatientLastName              string  `json:"patient_last_name"`
	PreferredCommunicationMethod *string `json:"preferred_communication_method,omitempty"`

	// From clinic_staff (nil until accepted)
	ProviderFirstName      *string `json:"provider_first_name,omitempty"`
	ProviderLastName       *string `json:"provider_last_name,omitempty"`
	ProviderSpecialization *string `json:"provider_specialization,omitempty"`
	ProviderTitle          *string `json:"provider_title,omitempty"`
}

// PatientConsultationSummaryResponse is the patient-facing history list item.
type PatientConsultationSummaryResponse struct {
	ID                     uuid.UUID                        `json:"id"`
	Status                 telemedicine.ConsultationStatus  `json:"status"`
	Channel                telemedicine.ConsultationChannel `json:"channel"`
	TriageLevelAtStart     *string                          `json:"triage_level_at_start,omitempty"`
	RequestedAt            *time.Time                       `json:"requested_at,omitempty"`
	StartedAt              *time.Time                       `json:"started_at,omitempty"`
	EndedAt                *time.Time                       `json:"ended_at,omitempty"`
	DurationSeconds        *int                             `json:"duration_seconds,omitempty"`
	ConsultationFee        *float64                         `json:"consultation_fee,omitempty"`
	PaymentStatus          telemedicine.PaymentStatus       `json:"payment_status"`
	PatientRating          *int                             `json:"patient_rating,omitempty"`
	ChiefComplaint         string                           `json:"chief_complaint"`
	ProviderFirstName      *string                          `json:"provider_first_name,omitempty"`
	ProviderLastName       *string                          `json:"provider_last_name,omitempty"`
	ProviderSpecialization *string                          `json:"provider_specialization,omitempty"`
}

// ProviderActiveConsultationResponse is the provider dashboard list item.
type ProviderActiveConsultationResponse struct {
	ID                           uuid.UUID                        `json:"id"`
	Status                       telemedicine.ConsultationStatus  `json:"status"`
	TriageLevelAtStart           *string                          `json:"triage_level_at_start,omitempty"`
	RequestedAt                  *time.Time                       `json:"requested_at,omitempty"`
	StartedAt                    *time.Time                       `json:"started_at,omitempty"`
	Channel                      telemedicine.ConsultationChannel `json:"channel"`
	PatientFirstName             string                           `json:"patient_first_name"`
	PatientLastName              string                           `json:"patient_last_name"`
	PreferredCommunicationMethod *string                          `json:"preferred_communication_method,omitempty"`
	RequiresInterpreter          bool                             `json:"requires_interpreter"`
	ChiefComplaint               string                           `json:"chief_complaint"`
	AISummary                    *string                          `json:"ai_summary,omitempty"`
	SeverityScore                *int                             `json:"severity_score,omitempty"`
	UnreadMessages               int64                            `json:"unread_messages"`
}

// WaitingRoomEntryResponse is the provider-facing waiting room list item.
type WaitingRoomEntryResponse struct {
	ID                 uuid.UUID                        `json:"id"`
	TriageLevelAtStart *string                          `json:"triage_level_at_start,omitempty"`
	RequestedAt        *time.Time                       `json:"requested_at,omitempty"`
	Channel            telemedicine.ConsultationChannel `json:"channel"`
	ConsultationFee    *float64                         `json:"consultation_fee,omitempty"`
	PatientFirstName   string                           `json:"patient_first_name"`
	PatientLastName    string                           `json:"patient_last_name"`
	ChiefComplaint     string                           `json:"chief_complaint"`
	SeverityScore      *int                             `json:"severity_score,omitempty"`
	AISummary          *string                          `json:"ai_summary,omitempty"`
}

// ProviderConsultationHistoryEntryResponse is the provider history list item.
type ProviderConsultationHistoryEntryResponse struct {
	ID               uuid.UUID                           `json:"id"`
	Status           telemedicine.ConsultationStatus     `json:"status"`
	Channel          telemedicine.ConsultationChannel    `json:"channel"`
	RequestedAt      *time.Time                          `json:"requested_at,omitempty"`
	EndedAt          *time.Time                          `json:"ended_at,omitempty"`
	DurationSeconds  *int                                `json:"duration_seconds,omitempty"`
	ConsultationFee  *float64                            `json:"consultation_fee,omitempty"`
	PaymentStatus    telemedicine.PaymentStatus          `json:"payment_status"`
	PatientRating    *int                                `json:"patient_rating,omitempty"`
	EndReason        *telemedicine.ConsultationEndReason `json:"end_reason,omitempty"`
	PatientFirstName string                              `json:"patient_first_name"`
	PatientLastName  string                              `json:"patient_last_name"`
	ChiefComplaint   string                              `json:"chief_complaint"`
}

// ActiveConsultationCheckResponse is the minimal projection used to signal an
// already-active consultation to the patient.
type ActiveConsultationCheckResponse struct {
	ID              uuid.UUID                        `json:"id"`
	Status          telemedicine.ConsultationStatus  `json:"status"`
	ProviderStaffID *uuid.UUID                       `json:"provider_staff_id,omitempty"`
	Channel         telemedicine.ConsultationChannel `json:"channel"`
}

// ─── List wrappers ─────────────────────────────────────────────────────────────

// PatientConsultationsResponse wraps the paginated patient history list.
type PatientConsultationsResponse struct {
	Consultations []PatientConsultationSummaryResponse `json:"consultations"`
	Count         int                                  `json:"count"`
	Limit         int                                  `json:"limit"`
	Offset        int                                  `json:"offset"`
}

// ProviderActiveConsultationsResponse wraps the provider dashboard list.
type ProviderActiveConsultationsResponse struct {
	Consultations []ProviderActiveConsultationResponse `json:"consultations"`
	Count         int                                  `json:"count"`
}

// WaitingRoomResponse wraps the waiting room list.
type WaitingRoomResponse struct {
	Entries []WaitingRoomEntryResponse `json:"entries"`
	Count   int                        `json:"count"`
}

// ProviderConsultationHistoryResponse wraps the paginated provider history list.
type ProviderConsultationHistoryResponse struct {
	Consultations []ProviderConsultationHistoryEntryResponse `json:"consultations"`
	Count         int                                        `json:"count"`
	Limit         int                                        `json:"limit"`
	Offset        int                                        `json:"offset"`
}

// ─── Conversion helpers ────────────────────────────────────────────────────────

// ToConsultationResponse converts a domain Consultation to its response DTO.
func ToConsultationResponse(c telemedicine.Consultation) ConsultationResponse {
	return ConsultationResponse{
		ID:                    c.ID,
		SymptomSessionID:      c.SymptomSessionID,
		PatientID:             c.PatientID,
		ProviderStaffID:       c.ProviderStaffID,
		ClinicID:              c.ClinicID,
		Channel:               c.Channel,
		TriageLevelAtStart:    c.TriageLevelAtStart,
		RequestedAt:           c.RequestedAt,
		AcceptedAt:            c.AcceptedAt,
		StartedAt:             c.StartedAt,
		EndedAt:               c.EndedAt,
		DurationSeconds:       c.DurationSeconds,
		Status:                c.Status,
		EndedBy:               c.EndedBy,
		EndReason:             c.EndReason,
		ConsultationFee:       c.ConsultationFee,
		FeeCurrency:           c.FeeCurrency,
		PaymentStatus:         c.PaymentStatus,
		PaymentReference:      c.PaymentReference,
		PatientRating:         c.PatientRating,
		PatientFeedback:       c.PatientFeedback,
		RatedAt:               c.RatedAt,
		FollowUpAppointmentID: c.FollowUpAppointmentID,
		CreatedAt:             c.CreatedAt,
		UpdatedAt:             c.UpdatedAt,
	}
}

// ToConsultationWithDetailsResponse converts the rich hydrated domain view.
func ToConsultationWithDetailsResponse(c telemedicine.ConsultationWithDetails) ConsultationWithDetailsResponse {
	return ConsultationWithDetailsResponse{
		ConsultationResponse:         ToConsultationResponse(c.Consultation),
		ChiefComplaint:               c.ChiefComplaint,
		AISummary:                    c.AISummary,
		SessionTriageLevel:           c.SessionTriageLevel,
		SymptomsReported:             c.SymptomsReported,
		PatientFirstName:             c.PatientFirstName,
		PatientLastName:              c.PatientLastName,
		PreferredCommunicationMethod: c.PreferredCommunicationMethod,
		ProviderFirstName:            c.ProviderFirstName,
		ProviderLastName:             c.ProviderLastName,
		ProviderSpecialization:       c.ProviderSpecialization,
		ProviderTitle:                c.ProviderTitle,
	}
}

// ToPatientConsultationSummaryResponse converts a domain summary to its response DTO.
func ToPatientConsultationSummaryResponse(c telemedicine.PatientConsultationSummary) PatientConsultationSummaryResponse {
	return PatientConsultationSummaryResponse{
		ID:                     c.ID,
		Status:                 c.Status,
		Channel:                c.Channel,
		TriageLevelAtStart:     c.TriageLevelAtStart,
		RequestedAt:            c.RequestedAt,
		StartedAt:              c.StartedAt,
		EndedAt:                c.EndedAt,
		DurationSeconds:        c.DurationSeconds,
		ConsultationFee:        c.ConsultationFee,
		PaymentStatus:          c.PaymentStatus,
		PatientRating:          c.PatientRating,
		ChiefComplaint:         c.ChiefComplaint,
		ProviderFirstName:      c.ProviderFirstName,
		ProviderLastName:       c.ProviderLastName,
		ProviderSpecialization: c.ProviderSpecialization,
	}
}

// ToProviderActiveConsultationResponse converts the provider dashboard domain model.
func ToProviderActiveConsultationResponse(c telemedicine.ProviderActiveConsultation) ProviderActiveConsultationResponse {
	return ProviderActiveConsultationResponse{
		ID:                           c.ID,
		Status:                       c.Status,
		TriageLevelAtStart:           c.TriageLevelAtStart,
		RequestedAt:                  c.RequestedAt,
		StartedAt:                    c.StartedAt,
		Channel:                      c.Channel,
		PatientFirstName:             c.PatientFirstName,
		PatientLastName:              c.PatientLastName,
		PreferredCommunicationMethod: c.PreferredCommunicationMethod,
		RequiresInterpreter:          c.RequiresInterpreter,
		ChiefComplaint:               c.ChiefComplaint,
		AISummary:                    c.AISummary,
		SeverityScore:                c.SeverityScore,
		UnreadMessages:               c.UnreadMessages,
	}
}

// ToWaitingRoomEntryResponse converts a waiting room domain entry.
func ToWaitingRoomEntryResponse(e telemedicine.WaitingRoomEntry) WaitingRoomEntryResponse {
	return WaitingRoomEntryResponse{
		ID:                 e.ID,
		TriageLevelAtStart: e.TriageLevelAtStart,
		RequestedAt:        e.RequestedAt,
		Channel:            e.Channel,
		ConsultationFee:    e.ConsultationFee,
		PatientFirstName:   e.PatientFirstName,
		PatientLastName:    e.PatientLastName,
		ChiefComplaint:     e.ChiefComplaint,
		SeverityScore:      e.SeverityScore,
		AISummary:          e.AISummary,
	}
}

// ToProviderConsultationHistoryEntryResponse converts a provider history domain entry.
func ToProviderConsultationHistoryEntryResponse(e telemedicine.ProviderConsultationHistoryEntry) ProviderConsultationHistoryEntryResponse {
	return ProviderConsultationHistoryEntryResponse{
		ID:               e.ID,
		Status:           e.Status,
		Channel:          e.Channel,
		RequestedAt:      e.RequestedAt,
		EndedAt:          e.EndedAt,
		DurationSeconds:  e.DurationSeconds,
		ConsultationFee:  e.ConsultationFee,
		PaymentStatus:    e.PaymentStatus,
		PatientRating:    e.PatientRating,
		EndReason:        e.EndReason,
		PatientFirstName: e.PatientFirstName,
		PatientLastName:  e.PatientLastName,
		ChiefComplaint:   e.ChiefComplaint,
	}
}

// ToActiveConsultationCheckResponse converts the minimal active-check projection.
func ToActiveConsultationCheckResponse(c telemedicine.ActiveConsultationCheck) ActiveConsultationCheckResponse {
	return ActiveConsultationCheckResponse{
		ID:              c.ID,
		Status:          c.Status,
		ProviderStaffID: c.ProviderStaffID,
		Channel:         c.Channel,
	}
}

// ToDomainConsultation converts a RequestConsultationRequest to the domain model.
func ToDomainConsultation(req RequestConsultationRequest) telemedicine.Consultation {
	return telemedicine.Consultation{
		PatientID:        req.PatientID,
		SymptomSessionID: req.SymptomSessionID,
		Channel:          req.Channel,
		ConsultationFee:  req.ConsultationFee,
		FeeCurrency:      req.FeeCurrency,
		ProviderStaffID:  req.ProviderStaffID,
		ClinicID:         req.ClinicID,
	}
}
