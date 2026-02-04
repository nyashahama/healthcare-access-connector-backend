package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateEmergencyContactRequest represents a request to create an emergency contact
type CreateEmergencyContactRequest struct {
	PatientID            uuid.UUID `json:"patient_id"`
	ContactName          string    `json:"contact_name"`
	Relationship         string    `json:"relationship"`
	PhoneNumber          string    `json:"phone_number"`
	Email                *string   `json:"email,omitempty"`
	Address              *string   `json:"address,omitempty"`
	IsPrimary            bool      `json:"is_primary"`
	CanAccessMedicalInfo bool      `json:"can_access_medical_info"`
	AccessLevel          *string   `json:"access_level,omitempty"`
	RelationshipVerified bool      `json:"relationship_verified"`
	VerificationNotes    *string   `json:"verification_notes,omitempty"`
}

// UpdateEmergencyContactRequest represents a request to update an emergency contact
type UpdateEmergencyContactRequest struct {
	ContactName          string  `json:"contact_name"`
	Relationship         string  `json:"relationship"`
	PhoneNumber          string  `json:"phone_number"`
	Email                *string `json:"email,omitempty"`
	Address              *string `json:"address,omitempty"`
	IsPrimary            bool    `json:"is_primary"`
	CanAccessMedicalInfo bool    `json:"can_access_medical_info"`
	AccessLevel          *string `json:"access_level,omitempty"`
	RelationshipVerified bool    `json:"relationship_verified"`
	VerificationNotes    *string `json:"verification_notes,omitempty"`
}

// EmergencyContactResponse represents an emergency contact in responses
type EmergencyContactResponse struct {
	ID                   uuid.UUID `json:"id"`
	PatientID            uuid.UUID `json:"patient_id"`
	ContactName          string    `json:"contact_name"`
	Relationship         string    `json:"relationship"`
	PhoneNumber          string    `json:"phone_number"`
	Email                *string   `json:"email,omitempty"`
	Address              *string   `json:"address,omitempty"`
	IsPrimary            bool      `json:"is_primary"`
	CanAccessMedicalInfo bool      `json:"can_access_medical_info"`
	AccessLevel          *string   `json:"access_level,omitempty"`
	RelationshipVerified bool      `json:"relationship_verified"`
	VerificationNotes    *string   `json:"verification_notes,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// EmergencyContactsListResponse represents a list of emergency contacts
type EmergencyContactsListResponse struct {
	EmergencyContacts []EmergencyContactResponse `json:"emergency_contacts"`
	Count             int                        `json:"count"`
}

// ToEmergencyContactResponse converts domain EmergencyContact to response DTO
func ToEmergencyContactResponse(contact patients.EmergencyContact) EmergencyContactResponse {
	return EmergencyContactResponse{
		ID:                   contact.ID,
		PatientID:            contact.PatientID,
		ContactName:          contact.ContactName,
		Relationship:         contact.Relationship,
		PhoneNumber:          contact.PhoneNumber,
		Email:                contact.Email,
		Address:              contact.Address,
		IsPrimary:            contact.IsPrimary,
		CanAccessMedicalInfo: contact.CanAccessMedicalInfo,
		AccessLevel:          contact.AccessLevel,
		RelationshipVerified: contact.RelationshipVerified,
		VerificationNotes:    contact.VerificationNotes,
		CreatedAt:            contact.CreatedAt,
		UpdatedAt:            contact.UpdatedAt,
	}
}

// ToDomainEmergencyContact converts request DTO to domain model
func ToDomainEmergencyContact(req CreateEmergencyContactRequest) patients.EmergencyContact {
	return patients.EmergencyContact{
		PatientID:            req.PatientID,
		ContactName:          req.ContactName,
		Relationship:         req.Relationship,
		PhoneNumber:          req.PhoneNumber,
		Email:                req.Email,
		Address:              req.Address,
		IsPrimary:            req.IsPrimary,
		CanAccessMedicalInfo: req.CanAccessMedicalInfo,
		AccessLevel:          req.AccessLevel,
		RelationshipVerified: req.RelationshipVerified,
		VerificationNotes:    req.VerificationNotes,
	}
}

// UpdateToDomainEmergencyContact updates existing domain model with request data
func UpdateToDomainEmergencyContact(existing patients.EmergencyContact, req UpdateEmergencyContactRequest) patients.EmergencyContact {
	existing.ContactName = req.ContactName
	existing.Relationship = req.Relationship
	existing.PhoneNumber = req.PhoneNumber
	existing.Email = req.Email
	existing.Address = req.Address
	existing.IsPrimary = req.IsPrimary
	existing.CanAccessMedicalInfo = req.CanAccessMedicalInfo
	existing.AccessLevel = req.AccessLevel
	existing.RelationshipVerified = req.RelationshipVerified
	existing.VerificationNotes = req.VerificationNotes
	return existing
}
