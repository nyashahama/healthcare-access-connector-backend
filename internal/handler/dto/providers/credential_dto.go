package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// CreateCredentialRequest represents a request to create a credential
type CreateCredentialRequest struct {
	StaffID          uuid.UUID  `json:"staff_id"`
	CredentialType   string     `json:"credential_type"`
	CredentialNumber *string    `json:"credential_number,omitempty"`
	IssuingAuthority string     `json:"issuing_authority"`
	IssueDate        *time.Time `json:"issue_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	Status           string     `json:"status"`
	VerifiedBy       *uuid.UUID `json:"verified_by,omitempty"`
	DocumentURL      *string    `json:"document_url,omitempty"`
	Notes            *string    `json:"notes,omitempty"`
}

// UpdateCredentialRequest represents a request to update a credential
type UpdateCredentialRequest struct {
	CredentialType   string     `json:"credential_type"`
	CredentialNumber *string    `json:"credential_number,omitempty"`
	IssuingAuthority string     `json:"issuing_authority"`
	IssueDate        *time.Time `json:"issue_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	Status           string     `json:"status"`
	VerifiedBy       *uuid.UUID `json:"verified_by,omitempty"`
	DocumentURL      *string    `json:"document_url,omitempty"`
	Notes            *string    `json:"notes,omitempty"`
}

// CredentialResponse represents a credential in responses
type CredentialResponse struct {
	ID               uuid.UUID  `json:"id"`
	StaffID          uuid.UUID  `json:"staff_id"`
	CredentialType   string     `json:"credential_type"`
	CredentialNumber *string    `json:"credential_number,omitempty"`
	IssuingAuthority string     `json:"issuing_authority"`
	IssueDate        *time.Time `json:"issue_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	Status           string     `json:"status"`
	VerifiedBy       *uuid.UUID `json:"verified_by,omitempty"`
	VerificationDate *time.Time `json:"verification_date,omitempty"`
	DocumentURL      *string    `json:"document_url,omitempty"`
	Notes            *string    `json:"notes,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// CredentialListResponse represents a list of credentials
type CredentialListResponse struct {
	Credentials []CredentialResponse `json:"credentials"`
	Total       int                  `json:"total"`
	Limit       int                  `json:"limit,omitempty"`
	Offset      int                  `json:"offset,omitempty"`
}

// ToCredentialResponse converts domain ProfessionalCredential to response DTO
func ToCredentialResponse(credential providers.ProfessionalCredential) CredentialResponse {
	return CredentialResponse{
		ID:               credential.ID,
		StaffID:          credential.StaffID,
		CredentialType:   credential.CredentialType,
		CredentialNumber: credential.CredentialNumber,
		IssuingAuthority: credential.IssuingAuthority,
		IssueDate:        credential.IssueDate,
		ExpiryDate:       credential.ExpiryDate,
		Status:           credential.Status,
		VerifiedBy:       credential.VerifiedBy,
		VerificationDate: credential.VerificationDate,
		DocumentURL:      credential.DocumentURL,
		Notes:            credential.Notes,
		CreatedAt:        credential.CreatedAt,
		UpdatedAt:        credential.UpdatedAt,
	}
}

// ToDomainCredential converts request DTO to domain model
func ToDomainCredential(req CreateCredentialRequest) providers.ProfessionalCredential {
	return providers.ProfessionalCredential{
		StaffID:          req.StaffID,
		CredentialType:   req.CredentialType,
		CredentialNumber: req.CredentialNumber,
		IssuingAuthority: req.IssuingAuthority,
		IssueDate:        req.IssueDate,
		ExpiryDate:       req.ExpiryDate,
		Status:           req.Status,
		VerifiedBy:       req.VerifiedBy,
		DocumentURL:      req.DocumentURL,
		Notes:            req.Notes,
	}
}

// UpdateToDomainCredential updates existing domain model with request data
func UpdateToDomainCredential(existing providers.ProfessionalCredential, req UpdateCredentialRequest) providers.ProfessionalCredential {
	existing.CredentialType = req.CredentialType
	existing.CredentialNumber = req.CredentialNumber
	existing.IssuingAuthority = req.IssuingAuthority
	existing.IssueDate = req.IssueDate
	existing.ExpiryDate = req.ExpiryDate
	existing.Status = req.Status
	existing.VerifiedBy = req.VerifiedBy
	existing.DocumentURL = req.DocumentURL
	existing.Notes = req.Notes
	return existing
}
