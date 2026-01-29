package patients

import (
	"time"

	"github.com/google/uuid"
)

// EmergencyContact represents an emergency contact for a patient
type EmergencyContact struct {
	ID                   uuid.UUID `json:"id"`
	PatientID            uuid.UUID `json:"patient_id"`
	ContactName          string    `json:"contact_name"`
	Relationship         string    `json:"relationship"`
	PhoneNumber          string    `json:"phone_number"`
	Email                *string   `json:"email,omitempty"`
	Address              *string   `json:"address,omitempty"`
	IsPrimary            bool      `json:"is_primary"`
	CanAccessMedicalInfo bool      `json:"can_access_medical_info"`
	AccessLevel          *string   `json:"access_level,omitempty"` // 'full', 'limited', 'emergency_only'
	RelationshipVerified bool      `json:"relationship_verified"`
	VerificationNotes    *string   `json:"verification_notes,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// EmergencyContactStatistics provides statistics for emergency contacts
type EmergencyContactStatistics struct {
	TotalContacts      int64 `json:"total_contacts"`
	PrimaryContacts    int64 `json:"primary_contacts"`
	WithMedicalAccess  int64 `json:"with_medical_access"`
	VerifiedContacts   int64 `json:"verified_contacts"`
	FullAccessContacts int64 `json:"full_access_contacts"`
}

// EmergencyContactSystemMetrics provides system-wide emergency contact metrics
type EmergencyContactSystemMetrics struct {
	PatientsWithContacts  int64   `json:"patients_with_contacts"`
	TotalContacts         int64   `json:"total_contacts"`
	PrimaryContacts       int64   `json:"primary_contacts"`
	WithMedicalAccess     int64   `json:"with_medical_access"`
	UnverifiedContacts    int64   `json:"unverified_contacts"`
	AvgContactsPerPatient float64 `json:"avg_contacts_per_patient"`
}

// RelationshipDistribution represents distribution by relationship type
type RelationshipDistribution struct {
	Relationship string `json:"relationship"`
	ContactCount int64  `json:"contact_count"`
	PrimaryCount int64  `json:"primary_count"`
	WithAccess   int64  `json:"with_access"`
}

// AccessLevelDistribution represents distribution by access level
type AccessLevelDistribution struct {
	AccessLevel  string `json:"access_level"`
	ContactCount int64  `json:"contact_count"`
	PatientCount int64  `json:"patient_count"`
}
