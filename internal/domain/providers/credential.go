package providers

import (
	"time"

	"github.com/google/uuid"
)

// ProfessionalCredential represents a professional credential
type ProfessionalCredential struct {
	ID               uuid.UUID  `json:"id"`
	StaffID          uuid.UUID  `json:"staff_id"`
	CredentialType   string     `json:"credential_type"` // professional_license, specialization, degree, certification
	CredentialNumber *string    `json:"credential_number,omitempty"`
	IssuingAuthority string     `json:"issuing_authority"`
	IssueDate        *time.Time `json:"issue_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	Status           string     `json:"status"` // verified, pending, expired, revoked
	VerifiedBy       *uuid.UUID `json:"verified_by,omitempty"`
	VerificationDate *time.Time `json:"verification_date,omitempty"`
	DocumentURL      *string    `json:"document_url,omitempty"`
	Notes            *string    `json:"notes,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}