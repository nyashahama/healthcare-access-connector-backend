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

// ============================================
// SUPPORTING TYPES - CREDENTIAL REPOSITORY
// ============================================

type CredentialWithStaff struct {
	Credential ProfessionalCredential
	StaffInfo  StaffBasicInfo
}

type StaffBasicInfo struct {
	ID        uuid.UUID
	FirstName string
	LastName  string
	ClinicID  uuid.UUID
	WorkEmail *string
}

type CredentialStatistics struct {
	TotalCredentials int64
	VerifiedCount    int64
	PendingCount     int64
	ExpiredCount     int64
	RevokedCount     int64
	RejectedCount    int64
	OverdueRenewals  int64
}

type ClinicCredentialMetrics struct {
	TotalCredentials      int64
	VerifiedCredentials   int64
	PendingCredentials    int64
	ExpiredCredentials    int64
	StaffWithCredentials  int64
	AvgCredentialDuration *float64
}

type CredentialTypeDistribution struct {
	CredentialType string
	Count          int64
	VerifiedCount  int64
	ExpiredCount   int64
}

type CredentialStatusDistribution struct {
	Status     string
	Count      int64
	WithExpiry int64
}

type SystemCredentialMetrics struct {
	TotalCredentials          int64
	TotalStaffWithCredentials int64
	VerifiedCredentials       int64
	PendingVerifications      int64
	ExpiredCredentials        int64
	ExpiringSoon              int64
	UniqueAuthorities         int64
	AvgVerificationTimeDays   *float64
}

type VerificationBacklog struct {
	SubmissionDate time.Time
	PendingCount   int64
	AvgDaysPending *float64
}

type VerifierWorkload struct {
	VerifierID        uuid.UUID
	VerifierEmail     string
	VerifiedCount     int64
	FirstVerification *time.Time
	LastVerification  *time.Time
}
