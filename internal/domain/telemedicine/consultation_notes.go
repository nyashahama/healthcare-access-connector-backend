package telemedicine

import (
	"time"

	"github.com/google/uuid"
)

// ReferralType represents the kind of referral issued at the end of a consultation.
type ReferralType string

const (
	ReferralSpecialist     ReferralType = "specialist"
	ReferralEmergency      ReferralType = "emergency"
	ReferralInPersonClinic ReferralType = "in_person_clinic"
)

// PrescriptionItem is a single line in a prescription.
// It is stored as a JSONB array in prescription_details.
type PrescriptionItem struct {
	Name      string `json:"name"`
	Dosage    string `json:"dosage"`
	Frequency string `json:"frequency"`
	Duration  string `json:"duration"`
	Notes     string `json:"notes,omitempty"`
}

// ConsultationNote is the core domain model for a provider's SOAP clinical note.
// There is a strict 1-to-1 relationship with a consultation (enforced by UNIQUE constraint).
// Notes are created as drafts and locked via FinaliseNote.
type ConsultationNote struct {
	ID                  uuid.UUID `json:"id"`
	ConsultationID      uuid.UUID `json:"consultation_id"`
	AuthoredByStaffID   uuid.UUID `json:"authored_by_staff_id"`

	// SOAP format
	Subjective *string `json:"subjective,omitempty"` // S — patient-reported symptoms
	Objective  *string `json:"objective,omitempty"`  // O — observations / vitals
	Assessment *string `json:"assessment,omitempty"` // A — clinical impression
	Plan       *string `json:"plan,omitempty"`       // P — treatment plan / next steps

	// Diagnosis
	DiagnosisCodes []string `json:"diagnosis_codes,omitempty"` // ICD-10 codes

	// Prescription
	PrescriptionIssued  bool               `json:"prescription_issued"`
	PrescriptionDetails []PrescriptionItem `json:"prescription_details,omitempty"`

	// Referral
	ReferralRequired bool          `json:"referral_required"`
	ReferralType     *ReferralType `json:"referral_type,omitempty"`
	ReferralNotes    *string       `json:"referral_notes,omitempty"`

	// Follow-up
	FollowUpRecommended bool    `json:"follow_up_recommended"`
	FollowUpTimeframe   *string `json:"follow_up_timeframe,omitempty"`

	// Locking
	IsFinalised bool       `json:"is_finalised"`
	FinalisedAt *time.Time `json:"finalised_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ConsultationNoteWithProviderInfo is the hydrated view used in patient records
// and admin audits. It joins the note with the authoring provider's profile.
type ConsultationNoteWithProviderInfo struct {
	ConsultationNote

	// From clinic_staff
	ProviderFirstName    string  `json:"provider_first_name"`
	ProviderLastName     string  `json:"provider_last_name"`
	ProfessionalTitle    *string `json:"professional_title,omitempty"`
	Specialization       *string `json:"specialization,omitempty"`
	HPCSNumber           *string `json:"hpcs_number,omitempty"`
}

// ProviderNoteHistoryEntry is the provider note history list projection.
// It shows finalised notes with the patient's name so the provider can
// browse their own clinical record history.
type ProviderNoteHistoryEntry struct {
	ID                   uuid.UUID `json:"id"`
	ConsultationID       uuid.UUID `json:"consultation_id"`
	Assessment           *string   `json:"assessment,omitempty"`
	Plan                 *string   `json:"plan,omitempty"`
	DiagnosisCodes       []string  `json:"diagnosis_codes,omitempty"`
	PrescriptionIssued   bool      `json:"prescription_issued"`
	ReferralRequired     bool      `json:"referral_required"`
	FollowUpRecommended  bool      `json:"follow_up_recommended"`
	FinalisedAt          *time.Time `json:"finalised_at,omitempty"`

	// Joined from patient_profiles via consultations
	PatientFirstName string `json:"patient_first_name"`
	PatientLastName  string `json:"patient_last_name"`
}

// PatientNoteHistoryEntry is the patient's complete telemedicine clinical record.
// It shows all finalised notes across all their consultations with the
// authoring provider's details.
type PatientNoteHistoryEntry struct {
	ID             uuid.UUID `json:"id"`
	ConsultationID uuid.UUID `json:"consultation_id"`

	// SOAP (selective — patient-safe fields)
	Subjective *string  `json:"subjective,omitempty"`
	Assessment *string  `json:"assessment,omitempty"`
	Plan       *string  `json:"plan,omitempty"`

	DiagnosisCodes      []string           `json:"diagnosis_codes,omitempty"`
	PrescriptionIssued  bool               `json:"prescription_issued"`
	PrescriptionDetails []PrescriptionItem `json:"prescription_details,omitempty"`
	ReferralRequired    bool               `json:"referral_required"`
	ReferralType        *ReferralType      `json:"referral_type,omitempty"`
	FollowUpRecommended bool               `json:"follow_up_recommended"`
	FollowUpTimeframe   *string            `json:"follow_up_timeframe,omitempty"`
	FinalisedAt         *time.Time         `json:"finalised_at,omitempty"`

	// Joined from clinic_staff
	ProviderFirstName string  `json:"provider_first_name"`
	ProviderLastName  string  `json:"provider_last_name"`
	ProfessionalTitle *string `json:"professional_title,omitempty"`
}