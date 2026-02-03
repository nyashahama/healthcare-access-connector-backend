package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// DTOs for Credentials

type CreateCredentialRequest struct {
	StaffID          uuid.UUID  `json:"staff_id" binding:"required"`
	CredentialType   string     `json:"credential_type" binding:"required,oneof=professional_license specialization degree certification"`
	CredentialNumber *string    `json:"credential_number,omitempty"`
	IssuingAuthority string     `json:"issuing_authority" binding:"required,min=1"`
	IssueDate        *time.Time `json:"issue_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	Status           string     `json:"status" binding:"oneof=verified pending expired revoked"`
	VerifiedBy       *uuid.UUID `json:"verified_by,omitempty"`
	DocumentURL      *string    `json:"document_url,omitempty"`
	Notes            *string    `json:"notes,omitempty"`
}

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

type CredentialListResponse struct {
	Credentials []CredentialResponse `json:"credentials"`
	Total       int                  `json:"total"`
}

// Helper function to convert domain to response
func CredentialToResponse(cred providers.ProfessionalCredential) CredentialResponse {
	return CredentialResponse{
		ID:               cred.ID,
		StaffID:          cred.StaffID,
		CredentialType:   cred.CredentialType,
		CredentialNumber: cred.CredentialNumber,
		IssuingAuthority: cred.IssuingAuthority,
		IssueDate:        cred.IssueDate,
		ExpiryDate:       cred.ExpiryDate,
		Status:           cred.Status,
		VerifiedBy:       cred.VerifiedBy,
		VerificationDate: cred.VerificationDate,
		DocumentURL:      cred.DocumentURL,
		Notes:            cred.Notes,
		CreatedAt:        cred.CreatedAt,
		UpdatedAt:        cred.UpdatedAt,
	}
}
