package telemedicine

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
)

// ─── Request DTOs ──────────────────────────────────────────────────────────────

// CreateNoteRequest is the provider-facing payload for creating a draft SOAP
// clinical note for a consultation.
type CreateNoteRequest struct {
	AuthoredByStaffID uuid.UUID `json:"authored_by_staff_id"`

	// SOAP fields
	Subjective *string `json:"subjective,omitempty"`
	Objective  *string `json:"objective,omitempty"`
	Assessment *string `json:"assessment,omitempty"`
	Plan       *string `json:"plan,omitempty"`

	// Diagnosis
	DiagnosisCodes []string `json:"diagnosis_codes,omitempty"`

	// Prescription
	PrescriptionIssued  bool                            `json:"prescription_issued"`
	PrescriptionDetails []telemedicine.PrescriptionItem `json:"prescription_details,omitempty"`

	// Referral
	ReferralRequired bool                       `json:"referral_required"`
	ReferralType     *telemedicine.ReferralType `json:"referral_type,omitempty"`
	ReferralNotes    *string                    `json:"referral_notes,omitempty"`

	// Follow-up
	FollowUpRecommended bool    `json:"follow_up_recommended"`
	FollowUpTimeframe   *string `json:"follow_up_timeframe,omitempty"`
}

// UpdateNoteRequest is the provider-facing payload for updating a draft note.
// All fields are optional; only non-nil values are applied.
type UpdateNoteRequest struct {
	Subjective *string `json:"subjective,omitempty"`
	Objective  *string `json:"objective,omitempty"`
	Assessment *string `json:"assessment,omitempty"`
	Plan       *string `json:"plan,omitempty"`

	DiagnosisCodes []string `json:"diagnosis_codes,omitempty"`

	PrescriptionIssued  *bool                           `json:"prescription_issued,omitempty"`
	PrescriptionDetails []telemedicine.PrescriptionItem `json:"prescription_details,omitempty"`

	ReferralRequired *bool                      `json:"referral_required,omitempty"`
	ReferralType     *telemedicine.ReferralType `json:"referral_type,omitempty"`
	ReferralNotes    *string                    `json:"referral_notes,omitempty"`

	FollowUpRecommended *bool   `json:"follow_up_recommended,omitempty"`
	FollowUpTimeframe   *string `json:"follow_up_timeframe,omitempty"`
}

// GetProviderNoteHistoryRequest carries pagination params for the provider note
// history endpoint.
type GetProviderNoteHistoryRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// GetPatientNoteHistoryRequest carries pagination params for the patient
// clinical record endpoint.
type GetPatientNoteHistoryRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// ─── Response DTOs ─────────────────────────────────────────────────────────────

// ConsultationNoteResponse is the full note response returned after create,
// update, or individual GET.
type ConsultationNoteResponse struct {
	ID                  uuid.UUID                       `json:"id"`
	ConsultationID      uuid.UUID                       `json:"consultation_id"`
	AuthoredByStaffID   uuid.UUID                       `json:"authored_by_staff_id"`
	Subjective          *string                         `json:"subjective,omitempty"`
	Objective           *string                         `json:"objective,omitempty"`
	Assessment          *string                         `json:"assessment,omitempty"`
	Plan                *string                         `json:"plan,omitempty"`
	DiagnosisCodes      []string                        `json:"diagnosis_codes,omitempty"`
	PrescriptionIssued  bool                            `json:"prescription_issued"`
	PrescriptionDetails []telemedicine.PrescriptionItem `json:"prescription_details,omitempty"`
	ReferralRequired    bool                            `json:"referral_required"`
	ReferralType        *telemedicine.ReferralType      `json:"referral_type,omitempty"`
	ReferralNotes       *string                         `json:"referral_notes,omitempty"`
	FollowUpRecommended bool                            `json:"follow_up_recommended"`
	FollowUpTimeframe   *string                         `json:"follow_up_timeframe,omitempty"`
	IsFinalised         bool                            `json:"is_finalised"`
	FinalisedAt         *time.Time                      `json:"finalised_at,omitempty"`
	CreatedAt           time.Time                       `json:"created_at"`
	UpdatedAt           time.Time                       `json:"updated_at"`
}

// ConsultationNoteWithProviderInfoResponse is the hydrated view used in patient
// records and admin audits. Extends the base note with the authoring provider's
// profile.
type ConsultationNoteWithProviderInfoResponse struct {
	ConsultationNoteResponse

	ProviderFirstName string  `json:"provider_first_name"`
	ProviderLastName  string  `json:"provider_last_name"`
	ProfessionalTitle *string `json:"professional_title,omitempty"`
	Specialization    *string `json:"specialization,omitempty"`
	HPCSNumber        *string `json:"hpcs_number,omitempty"`
}

// ProviderNoteHistoryEntryResponse is the provider note history list item.
type ProviderNoteHistoryEntryResponse struct {
	ID                  uuid.UUID  `json:"id"`
	ConsultationID      uuid.UUID  `json:"consultation_id"`
	Assessment          *string    `json:"assessment,omitempty"`
	Plan                *string    `json:"plan,omitempty"`
	DiagnosisCodes      []string   `json:"diagnosis_codes,omitempty"`
	PrescriptionIssued  bool       `json:"prescription_issued"`
	ReferralRequired    bool       `json:"referral_required"`
	FollowUpRecommended bool       `json:"follow_up_recommended"`
	FinalisedAt         *time.Time `json:"finalised_at,omitempty"`
	PatientFirstName    string     `json:"patient_first_name"`
	PatientLastName     string     `json:"patient_last_name"`
}

// PatientNoteHistoryEntryResponse is the patient's complete telemedicine
// clinical record item, showing patient-safe SOAP fields alongside the
// authoring provider's details.
type PatientNoteHistoryEntryResponse struct {
	ID             uuid.UUID `json:"id"`
	ConsultationID uuid.UUID `json:"consultation_id"`
	Subjective     *string   `json:"subjective,omitempty"`
	Assessment     *string   `json:"assessment,omitempty"`
	Plan           *string   `json:"plan,omitempty"`

	DiagnosisCodes      []string                        `json:"diagnosis_codes,omitempty"`
	PrescriptionIssued  bool                            `json:"prescription_issued"`
	PrescriptionDetails []telemedicine.PrescriptionItem `json:"prescription_details,omitempty"`
	ReferralRequired    bool                            `json:"referral_required"`
	ReferralType        *telemedicine.ReferralType      `json:"referral_type,omitempty"`
	FollowUpRecommended bool                            `json:"follow_up_recommended"`
	FollowUpTimeframe   *string                         `json:"follow_up_timeframe,omitempty"`
	FinalisedAt         *time.Time                      `json:"finalised_at,omitempty"`

	ProviderFirstName string  `json:"provider_first_name"`
	ProviderLastName  string  `json:"provider_last_name"`
	ProfessionalTitle *string `json:"professional_title,omitempty"`
}

// ─── List wrappers ─────────────────────────────────────────────────────────────

// ProviderNoteHistoryResponse wraps the paginated provider note history.
type ProviderNoteHistoryResponse struct {
	Notes  []ProviderNoteHistoryEntryResponse `json:"notes"`
	Count  int                                `json:"count"`
	Limit  int                                `json:"limit"`
	Offset int                                `json:"offset"`
}

// PatientNoteHistoryResponse wraps the paginated patient clinical record.
type PatientNoteHistoryResponse struct {
	Notes  []PatientNoteHistoryEntryResponse `json:"notes"`
	Count  int                               `json:"count"`
	Limit  int                               `json:"limit"`
	Offset int                               `json:"offset"`
}

// ─── Conversion helpers ────────────────────────────────────────────────────────

// ToConsultationNoteResponse converts a domain ConsultationNote to its response DTO.
func ToConsultationNoteResponse(n telemedicine.ConsultationNote) ConsultationNoteResponse {
	return ConsultationNoteResponse{
		ID:                  n.ID,
		ConsultationID:      n.ConsultationID,
		AuthoredByStaffID:   n.AuthoredByStaffID,
		Subjective:          n.Subjective,
		Objective:           n.Objective,
		Assessment:          n.Assessment,
		Plan:                n.Plan,
		DiagnosisCodes:      n.DiagnosisCodes,
		PrescriptionIssued:  n.PrescriptionIssued,
		PrescriptionDetails: n.PrescriptionDetails,
		ReferralRequired:    n.ReferralRequired,
		ReferralType:        n.ReferralType,
		ReferralNotes:       n.ReferralNotes,
		FollowUpRecommended: n.FollowUpRecommended,
		FollowUpTimeframe:   n.FollowUpTimeframe,
		IsFinalised:         n.IsFinalised,
		FinalisedAt:         n.FinalisedAt,
		CreatedAt:           n.CreatedAt,
		UpdatedAt:           n.UpdatedAt,
	}
}

// ToConsultationNoteWithProviderInfoResponse converts the hydrated domain view.
func ToConsultationNoteWithProviderInfoResponse(n telemedicine.ConsultationNoteWithProviderInfo) ConsultationNoteWithProviderInfoResponse {
	return ConsultationNoteWithProviderInfoResponse{
		ConsultationNoteResponse: ToConsultationNoteResponse(n.ConsultationNote),
		ProviderFirstName:        n.ProviderFirstName,
		ProviderLastName:         n.ProviderLastName,
		ProfessionalTitle:        n.ProfessionalTitle,
		Specialization:           n.Specialization,
		HPCSNumber:               n.HPCSNumber,
	}
}

// ToProviderNoteHistoryEntryResponse converts a provider history list entry.
func ToProviderNoteHistoryEntryResponse(e telemedicine.ProviderNoteHistoryEntry) ProviderNoteHistoryEntryResponse {
	return ProviderNoteHistoryEntryResponse{
		ID:                  e.ID,
		ConsultationID:      e.ConsultationID,
		Assessment:          e.Assessment,
		Plan:                e.Plan,
		DiagnosisCodes:      e.DiagnosisCodes,
		PrescriptionIssued:  e.PrescriptionIssued,
		ReferralRequired:    e.ReferralRequired,
		FollowUpRecommended: e.FollowUpRecommended,
		FinalisedAt:         e.FinalisedAt,
		PatientFirstName:    e.PatientFirstName,
		PatientLastName:     e.PatientLastName,
	}
}

// ToPatientNoteHistoryEntryResponse converts a patient clinical record entry.
func ToPatientNoteHistoryEntryResponse(e telemedicine.PatientNoteHistoryEntry) PatientNoteHistoryEntryResponse {
	return PatientNoteHistoryEntryResponse{
		ID:                  e.ID,
		ConsultationID:      e.ConsultationID,
		Subjective:          e.Subjective,
		Assessment:          e.Assessment,
		Plan:                e.Plan,
		DiagnosisCodes:      e.DiagnosisCodes,
		PrescriptionIssued:  e.PrescriptionIssued,
		PrescriptionDetails: e.PrescriptionDetails,
		ReferralRequired:    e.ReferralRequired,
		ReferralType:        e.ReferralType,
		FollowUpRecommended: e.FollowUpRecommended,
		FollowUpTimeframe:   e.FollowUpTimeframe,
		FinalisedAt:         e.FinalisedAt,
		ProviderFirstName:   e.ProviderFirstName,
		ProviderLastName:    e.ProviderLastName,
		ProfessionalTitle:   e.ProfessionalTitle,
	}
}

// ToDomainNote converts a CreateNoteRequest to the domain ConsultationNote.
func ToDomainNote(consultationID uuid.UUID, req CreateNoteRequest) telemedicine.ConsultationNote {
	return telemedicine.ConsultationNote{
		ConsultationID:      consultationID,
		AuthoredByStaffID:   req.AuthoredByStaffID,
		Subjective:          req.Subjective,
		Objective:           req.Objective,
		Assessment:          req.Assessment,
		Plan:                req.Plan,
		DiagnosisCodes:      req.DiagnosisCodes,
		PrescriptionIssued:  req.PrescriptionIssued,
		PrescriptionDetails: req.PrescriptionDetails,
		ReferralRequired:    req.ReferralRequired,
		ReferralType:        req.ReferralType,
		ReferralNotes:       req.ReferralNotes,
		FollowUpRecommended: req.FollowUpRecommended,
		FollowUpTimeframe:   req.FollowUpTimeframe,
	}
}
