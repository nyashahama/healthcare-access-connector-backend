package telemedicine

import (
	"time"

	"github.com/google/uuid"
)

// TriageLevel represents the urgency level assigned to a symptom session
type TriageLevel string

const (
	TriageLow       TriageLevel = "low"
	TriageMedium    TriageLevel = "medium"
	TriageHigh      TriageLevel = "high"
	TriageEmergency TriageLevel = "emergency"
)

// RecommendedAction represents the AI-generated care pathway recommendation
type RecommendedAction string

const (
	ActionTelemedicine RecommendedAction = "telemedicine"
	ActionVisitClinic  RecommendedAction = "visit_clinic"
	ActionEmergency    RecommendedAction = "emergency"
	ActionSelfCare     RecommendedAction = "self_care"
)

// SessionStatus represents the lifecycle state of a symptom checker session
type SessionStatus string

const (
	StatusCompleted        SessionStatus = "completed"
	StatusAbandoned        SessionStatus = "abandoned"
	StatusConvertedConsult SessionStatus = "converted_to_consult"
)

// SymptomCheckerSession is the core domain model for a symptom checker interaction.
// It captures what the patient reported, the AI triage output, and the session lifecycle.
type SymptomCheckerSession struct {
	ID        uuid.UUID `json:"id"`
	PatientID uuid.UUID `json:"patient_id"`
	UserID    uuid.UUID `json:"user_id"`
	// DependentID is set when the session was filed on behalf of a dependent
	DependentID *uuid.UUID `json:"dependent_id,omitempty"`

	// Patient-reported input
	ChiefComplaint      string   `json:"chief_complaint"`
	SymptomDuration     *string  `json:"symptom_duration,omitempty"`
	SymptomsReported    []string `json:"symptoms_reported"`
	BodySystemsAffected []string `json:"body_systems_affected,omitempty"`
	SeverityScore       *int     `json:"severity_score,omitempty"` // 1–10
	IsForDependent      bool     `json:"is_for_dependent"`

	// AI-generated triage output
	TriageLevel       TriageLevel       `json:"triage_level"`
	AISummary         *string           `json:"ai_summary,omitempty"`
	RecommendedAction RecommendedAction `json:"recommended_action"`

	// Session lifecycle
	Status     SessionStatus          `json:"status"`
	RawAnswers map[string]interface{} `json:"raw_answers,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SymptomSessionSummary is a lightweight projection used in list views (patient history).
type SymptomSessionSummary struct {
	ID                uuid.UUID         `json:"id"`
	ChiefComplaint    string            `json:"chief_complaint"`
	TriageLevel       TriageLevel       `json:"triage_level"`
	RecommendedAction RecommendedAction `json:"recommended_action"`
	SeverityScore     *int              `json:"severity_score,omitempty"`
	Status            SessionStatus     `json:"status"`
	IsForDependent    bool              `json:"is_for_dependent"`
	DependentID       *uuid.UUID        `json:"dependent_id,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// DependentSessionSummary is a lightweight projection for dependent-specific history lists.
type DependentSessionSummary struct {
	ID                uuid.UUID         `json:"id"`
	ChiefComplaint    string            `json:"chief_complaint"`
	TriageLevel       TriageLevel       `json:"triage_level"`
	RecommendedAction RecommendedAction `json:"recommended_action"`
	SeverityScore     *int              `json:"severity_score,omitempty"`
	Status            SessionStatus     `json:"status"`
	CreatedAt         time.Time         `json:"created_at"`
}

// EligibleSession is the preflight projection returned before showing the provider list.
// It confirms a recent telemedicine-eligible session exists for the patient.
type EligibleSession struct {
	ID                  uuid.UUID         `json:"id"`
	TriageLevel         TriageLevel       `json:"triage_level"`
	AISummary           *string           `json:"ai_summary,omitempty"`
	RecommendedAction   RecommendedAction `json:"recommended_action"`
	ChiefComplaint      string            `json:"chief_complaint"`
	SymptomsReported    []string          `json:"symptoms_reported"`
	BodySystemsAffected []string          `json:"body_systems_affected,omitempty"`
	SeverityScore       *int              `json:"severity_score,omitempty"`
	IsForDependent      bool              `json:"is_for_dependent"`
	DependentID         *uuid.UUID        `json:"dependent_id,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
}

// SessionWithPatientContext is the rich provider-facing view returned when a
// consultation is accepted. It joins session data with patient demographics
// and medical summary.
type SessionWithPatientContext struct {
	// Session fields
	SessionID           uuid.UUID         `json:"session_id"`
	ChiefComplaint      string            `json:"chief_complaint"`
	SymptomDuration     *string           `json:"symptom_duration,omitempty"`
	SymptomsReported    []string          `json:"symptoms_reported"`
	BodySystemsAffected []string          `json:"body_systems_affected,omitempty"`
	SeverityScore       *int              `json:"severity_score,omitempty"`
	TriageLevel         TriageLevel       `json:"triage_level"`
	AISummary           *string           `json:"ai_summary,omitempty"`
	RecommendedAction   RecommendedAction `json:"recommended_action"`
	IsForDependent      bool              `json:"is_for_dependent"`
	DependentID         *uuid.UUID        `json:"dependent_id,omitempty"`

	// Patient demographics (from patient_profiles)
	PatientID                    uuid.UUID  `json:"patient_id"`
	FirstName                    string     `json:"first_name"`
	LastName                     string     `json:"last_name"`
	DateOfBirth                  *time.Time `json:"date_of_birth,omitempty"`
	Gender                       *string    `json:"gender,omitempty"`
	PreferredCommunicationMethod *string    `json:"preferred_communication_method,omitempty"`
	LanguagePreferences          []string   `json:"language_preferences,omitempty"`
	RequiresInterpreter          bool       `json:"requires_interpreter"`

	// Medical summary (from patient_medical_info — left-joined, may be nil)
	BloodType           *string `json:"blood_type,omitempty"`
	OverallHealthStatus *string `json:"overall_health_status,omitempty"`
	HealthSummary       *string `json:"health_summary,omitempty"`
}

// AdminSessionSummary is used in triage-level admin/analytics list queries.
type AdminSessionSummary struct {
	ID                uuid.UUID         `json:"id"`
	PatientID         uuid.UUID         `json:"patient_id"`
	TriageLevel       TriageLevel       `json:"triage_level"`
	RecommendedAction RecommendedAction `json:"recommended_action"`
	SeverityScore     *int              `json:"severity_score,omitempty"`
	Status            SessionStatus     `json:"status"`
	CreatedAt         time.Time         `json:"created_at"`
}

// SessionOutcomeCount is returned by the analytics count query.
type SessionOutcomeCount struct {
	RecommendedAction RecommendedAction `json:"recommended_action"`
	Total             int64             `json:"total"`
}
