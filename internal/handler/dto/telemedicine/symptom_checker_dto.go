package telemedicine

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
)

// ─── Request DTOs ──────────────────────────────────────────────────────────────

// SubmitSessionRequest is the patient-facing payload for starting a new symptom
// checker session. The handler maps this to a domain SymptomCheckerSession.
type SubmitSessionRequest struct {
	PatientID           uuid.UUID              `json:"patient_id"`
	UserID              uuid.UUID              `json:"user_id"`
	DependentID         *uuid.UUID             `json:"dependent_id,omitempty"`
	ChiefComplaint      string                 `json:"chief_complaint"`
	SymptomDuration     *string                `json:"symptom_duration,omitempty"`
	SymptomsReported    []string               `json:"symptoms_reported"`
	BodySystemsAffected []string               `json:"body_systems_affected,omitempty"`
	SeverityScore       *int                   `json:"severity_score,omitempty"` // 1–10
	IsForDependent      bool                   `json:"is_for_dependent"`
	RawAnswers          map[string]interface{} `json:"raw_answers,omitempty"`
}

// AbandonSessionRequest carries the patient ID needed to authorise the mutation.
type AbandonSessionRequest struct {
	PatientID uuid.UUID `json:"patient_id"`
}

// GetSessionsByTriageLevelRequest is used for the admin analytics endpoint.
// From/To are ISO-8601 strings parsed by the handler.
type GetSessionsByTriageLevelRequest struct {
	TriageLevel string `json:"triage_level"`
	From        string `json:"from"` // "2006-01-02"
	To          string `json:"to"`   // "2006-01-02"
	Limit       int    `json:"limit,omitempty"`
	Offset      int    `json:"offset,omitempty"`
}

// ─── Response DTOs ─────────────────────────────────────────────────────────────

// SymptomSessionResponse is the full session response returned after submit or
// individual GET.
type SymptomSessionResponse struct {
	ID                  uuid.UUID              `json:"id"`
	PatientID           uuid.UUID              `json:"patient_id"`
	UserID              uuid.UUID              `json:"user_id"`
	DependentID         *uuid.UUID             `json:"dependent_id,omitempty"`
	ChiefComplaint      string                 `json:"chief_complaint"`
	SymptomDuration     *string                `json:"symptom_duration,omitempty"`
	SymptomsReported    []string               `json:"symptoms_reported"`
	BodySystemsAffected []string               `json:"body_systems_affected,omitempty"`
	SeverityScore       *int                   `json:"severity_score,omitempty"`
	IsForDependent      bool                   `json:"is_for_dependent"`
	TriageLevel         string                 `json:"triage_level"`
	AISummary           *string                `json:"ai_summary,omitempty"`
	RecommendedAction   string                 `json:"recommended_action"`
	Status              string                 `json:"status"`
	RawAnswers          map[string]interface{} `json:"raw_answers,omitempty"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// SymptomSessionSummaryResponse is the lightweight list item returned in
// patient history endpoints.
type SymptomSessionSummaryResponse struct {
	ID                uuid.UUID  `json:"id"`
	ChiefComplaint    string     `json:"chief_complaint"`
	TriageLevel       string     `json:"triage_level"`
	RecommendedAction string     `json:"recommended_action"`
	SeverityScore     *int       `json:"severity_score,omitempty"`
	Status            string     `json:"status"`
	IsForDependent    bool       `json:"is_for_dependent"`
	DependentID       *uuid.UUID `json:"dependent_id,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// DependentSessionSummaryResponse is the lightweight list item returned when
// fetching sessions for a specific dependent.
type DependentSessionSummaryResponse struct {
	ID                uuid.UUID `json:"id"`
	ChiefComplaint    string    `json:"chief_complaint"`
	TriageLevel       string    `json:"triage_level"`
	RecommendedAction string    `json:"recommended_action"`
	SeverityScore     *int      `json:"severity_score,omitempty"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
}

// EligibleSessionResponse is returned from the preflight check before the
// patient is shown the provider list.
type EligibleSessionResponse struct {
	ID                  uuid.UUID  `json:"id"`
	TriageLevel         string     `json:"triage_level"`
	AISummary           *string    `json:"ai_summary,omitempty"`
	RecommendedAction   string     `json:"recommended_action"`
	ChiefComplaint      string     `json:"chief_complaint"`
	SymptomsReported    []string   `json:"symptoms_reported"`
	BodySystemsAffected []string   `json:"body_systems_affected,omitempty"`
	SeverityScore       *int       `json:"severity_score,omitempty"`
	IsForDependent      bool       `json:"is_for_dependent"`
	DependentID         *uuid.UUID `json:"dependent_id,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// SessionWithPatientContextResponse is the rich provider-facing view.
type SessionWithPatientContextResponse struct {
	// Session fields
	SessionID           uuid.UUID  `json:"session_id"`
	ChiefComplaint      string     `json:"chief_complaint"`
	SymptomDuration     *string    `json:"symptom_duration,omitempty"`
	SymptomsReported    []string   `json:"symptoms_reported"`
	BodySystemsAffected []string   `json:"body_systems_affected,omitempty"`
	SeverityScore       *int       `json:"severity_score,omitempty"`
	TriageLevel         string     `json:"triage_level"`
	AISummary           *string    `json:"ai_summary,omitempty"`
	RecommendedAction   string     `json:"recommended_action"`
	IsForDependent      bool       `json:"is_for_dependent"`
	DependentID         *uuid.UUID `json:"dependent_id,omitempty"`

	// Patient demographics
	PatientID                    uuid.UUID  `json:"patient_id"`
	FirstName                    string     `json:"first_name"`
	LastName                     string     `json:"last_name"`
	DateOfBirth                  *time.Time `json:"date_of_birth,omitempty"`
	Gender                       *string    `json:"gender,omitempty"`
	PreferredCommunicationMethod *string    `json:"preferred_communication_method,omitempty"`
	LanguagePreferences          []string   `json:"language_preferences,omitempty"`
	RequiresInterpreter          bool       `json:"requires_interpreter"`

	// Medical summary
	BloodType           *string `json:"blood_type,omitempty"`
	OverallHealthStatus *string `json:"overall_health_status,omitempty"`
	HealthSummary       *string `json:"health_summary,omitempty"`
}

// AdminSessionSummaryResponse is the triage-level admin list item.
type AdminSessionSummaryResponse struct {
	ID                uuid.UUID `json:"id"`
	PatientID         uuid.UUID `json:"patient_id"`
	TriageLevel       string    `json:"triage_level"`
	RecommendedAction string    `json:"recommended_action"`
	SeverityScore     *int      `json:"severity_score,omitempty"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
}

// SessionOutcomeCountResponse represents a single outcome bucket in the
// analytics count response.
type SessionOutcomeCountResponse struct {
	RecommendedAction string `json:"recommended_action"`
	Total             int64  `json:"total"`
}

// PatientSessionsResponse wraps the paginated patient history list.
type PatientSessionsResponse struct {
	Sessions []SymptomSessionSummaryResponse `json:"sessions"`
	Count    int                             `json:"count"`
	Limit    int                             `json:"limit"`
	Offset   int                             `json:"offset"`
}

// DependentSessionsResponse wraps the dependent history list.
type DependentSessionsResponse struct {
	Sessions []DependentSessionSummaryResponse `json:"sessions"`
	Count    int                               `json:"count"`
}

// AdminSessionsResponse wraps the admin triage list.
type AdminSessionsResponse struct {
	Sessions []AdminSessionSummaryResponse `json:"sessions"`
	Count    int                           `json:"count"`
	Limit    int                           `json:"limit"`
	Offset   int                           `json:"offset"`
}

// OutcomeCountsResponse wraps the analytics count list.
type OutcomeCountsResponse struct {
	Counts []SessionOutcomeCountResponse `json:"counts"`
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

// ─── Conversion helpers ────────────────────────────────────────────────────────

// ToDomainSession converts a SubmitSessionRequest to the domain model.
func ToDomainSession(req SubmitSessionRequest) telemedicine.SymptomCheckerSession {
	return telemedicine.SymptomCheckerSession{
		PatientID:           req.PatientID,
		UserID:              req.UserID,
		DependentID:         req.DependentID,
		ChiefComplaint:      req.ChiefComplaint,
		SymptomDuration:     req.SymptomDuration,
		SymptomsReported:    req.SymptomsReported,
		BodySystemsAffected: req.BodySystemsAffected,
		SeverityScore:       req.SeverityScore,
		IsForDependent:      req.IsForDependent,
		RawAnswers:          req.RawAnswers,
	}
}

// ToSessionResponse converts a full domain session to its response DTO.
func ToSessionResponse(s telemedicine.SymptomCheckerSession) SymptomSessionResponse {
	return SymptomSessionResponse{
		ID:                  s.ID,
		PatientID:           s.PatientID,
		UserID:              s.UserID,
		DependentID:         s.DependentID,
		ChiefComplaint:      s.ChiefComplaint,
		SymptomDuration:     s.SymptomDuration,
		SymptomsReported:    s.SymptomsReported,
		BodySystemsAffected: s.BodySystemsAffected,
		SeverityScore:       s.SeverityScore,
		IsForDependent:      s.IsForDependent,
		TriageLevel:         string(s.TriageLevel),
		AISummary:           s.AISummary,
		RecommendedAction:   string(s.RecommendedAction),
		Status:              string(s.Status),
		RawAnswers:          s.RawAnswers,
		CreatedAt:           s.CreatedAt,
		UpdatedAt:           s.UpdatedAt,
	}
}

// ToSessionSummaryResponse converts a domain summary to its response DTO.
func ToSessionSummaryResponse(s telemedicine.SymptomSessionSummary) SymptomSessionSummaryResponse {
	return SymptomSessionSummaryResponse{
		ID:                s.ID,
		ChiefComplaint:    s.ChiefComplaint,
		TriageLevel:       string(s.TriageLevel),
		RecommendedAction: string(s.RecommendedAction),
		SeverityScore:     s.SeverityScore,
		Status:            string(s.Status),
		IsForDependent:    s.IsForDependent,
		DependentID:       s.DependentID,
		CreatedAt:         s.CreatedAt,
	}
}

// ToDependentSessionSummaryResponse converts a dependent session summary.
func ToDependentSessionSummaryResponse(s telemedicine.DependentSessionSummary) DependentSessionSummaryResponse {
	return DependentSessionSummaryResponse{
		ID:                s.ID,
		ChiefComplaint:    s.ChiefComplaint,
		TriageLevel:       string(s.TriageLevel),
		RecommendedAction: string(s.RecommendedAction),
		SeverityScore:     s.SeverityScore,
		Status:            string(s.Status),
		CreatedAt:         s.CreatedAt,
	}
}

// ToEligibleSessionResponse converts an EligibleSession domain model.
func ToEligibleSessionResponse(s telemedicine.EligibleSession) EligibleSessionResponse {
	return EligibleSessionResponse{
		ID:                  s.ID,
		TriageLevel:         string(s.TriageLevel),
		AISummary:           s.AISummary,
		RecommendedAction:   string(s.RecommendedAction),
		ChiefComplaint:      s.ChiefComplaint,
		SymptomsReported:    s.SymptomsReported,
		BodySystemsAffected: s.BodySystemsAffected,
		SeverityScore:       s.SeverityScore,
		IsForDependent:      s.IsForDependent,
		DependentID:         s.DependentID,
		CreatedAt:           s.CreatedAt,
	}
}

// ToSessionWithPatientContextResponse converts the rich provider-facing view.
func ToSessionWithPatientContextResponse(s telemedicine.SessionWithPatientContext) SessionWithPatientContextResponse {
	return SessionWithPatientContextResponse{
		SessionID:                    s.SessionID,
		ChiefComplaint:               s.ChiefComplaint,
		SymptomDuration:              s.SymptomDuration,
		SymptomsReported:             s.SymptomsReported,
		BodySystemsAffected:          s.BodySystemsAffected,
		SeverityScore:                s.SeverityScore,
		TriageLevel:                  string(s.TriageLevel),
		AISummary:                    s.AISummary,
		RecommendedAction:            string(s.RecommendedAction),
		IsForDependent:               s.IsForDependent,
		DependentID:                  s.DependentID,
		PatientID:                    s.PatientID,
		FirstName:                    s.FirstName,
		LastName:                     s.LastName,
		DateOfBirth:                  s.DateOfBirth,
		Gender:                       s.Gender,
		PreferredCommunicationMethod: s.PreferredCommunicationMethod,
		LanguagePreferences:          s.LanguagePreferences,
		RequiresInterpreter:          s.RequiresInterpreter,
		BloodType:                    s.BloodType,
		OverallHealthStatus:          s.OverallHealthStatus,
		HealthSummary:                s.HealthSummary,
	}
}

// ToAdminSessionSummaryResponse converts an admin session summary.
func ToAdminSessionSummaryResponse(s telemedicine.AdminSessionSummary) AdminSessionSummaryResponse {
	return AdminSessionSummaryResponse{
		ID:                s.ID,
		PatientID:         s.PatientID,
		TriageLevel:       string(s.TriageLevel),
		RecommendedAction: string(s.RecommendedAction),
		SeverityScore:     s.SeverityScore,
		Status:            string(s.Status),
		CreatedAt:         s.CreatedAt,
	}
}

// ToOutcomeCountResponse converts a session outcome count.
func ToOutcomeCountResponse(c telemedicine.SessionOutcomeCount) SessionOutcomeCountResponse {
	return SessionOutcomeCountResponse{
		RecommendedAction: string(c.RecommendedAction),
		Total:             c.Total,
	}
}
