package core

import (
	"time"

	"github.com/google/uuid"
)

// User represents a system user with role-based access
type User struct {
	ID                   uuid.UUID  `json:"id"`
	Email                *string    `json:"email,omitempty"`
	Phone                *string    `json:"phone,omitempty"`
	Role                 string     `json:"role"`   // patient, caregiver, provider, clinic_admin, system_admin, ngo_partner
	Status               string     `json:"status"` // active, inactive, pending_verification, suspended
	IsVerified           bool       `json:"is_verified"`
	VerificationToken    *string    `json:"-"`
	VerificationExpires  *time.Time `json:"-"`
	ResetPasswordToken   *string    `json:"-"`
	ResetPasswordExpires *time.Time `json:"-"`
	LastLogin            *time.Time `json:"last_login,omitempty"`
	LoginCount           int        `json:"login_count"`
	IsSMSOnly            bool       `json:"is_sms_only"`
	SMSConsentGiven      bool       `json:"sms_consent_given"`
	POPIAConsentGiven    bool       `json:"popia_consent_given"`
	ConsentDate          *time.Time `json:"consent_date,omitempty"`
	ProfileCompletionPct int        `json:"profile_completion_percentage"`

	// NEW: Provider onboarding fields
	PrimaryClinicID     *uuid.UUID `json:"primary_clinic_id,omitempty"`
	OnboardingCompleted bool       `json:"onboarding_completed"`
	OnboardingStep      *string    `json:"onboarding_step,omitempty"` // 'account_created', 'clinic_registered', 'clinic_approved', 'completed'

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProviderWithClinic represents a provider user with their clinic information
type ProviderWithClinic struct {
	UserID              uuid.UUID  `json:"user_id"`
	Email               *string    `json:"email,omitempty"`
	Phone               *string    `json:"phone,omitempty"`
	Role                string     `json:"role"`
	Status              string     `json:"status"`
	IsVerified          bool       `json:"is_verified"`
	PrimaryClinicID     *uuid.UUID `json:"primary_clinic_id,omitempty"`
	OnboardingCompleted bool       `json:"onboarding_completed"`
	OnboardingStep      *string    `json:"onboarding_step,omitempty"`

	// Clinic information
	ClinicID                 *uuid.UUID `json:"clinic_id,omitempty"`
	ClinicName               *string    `json:"clinic_name,omitempty"`
	ClinicVerificationStatus *string    `json:"clinic_verification_status,omitempty"`
	ClinicIsVerified         *bool      `json:"clinic_is_verified,omitempty"`
}

// UserClinic represents a clinic that a user is affiliated with
type UserClinic struct {
	ClinicID               uuid.UUID `json:"clinic_id"`
	ClinicName             string    `json:"clinic_name"`
	ClinicType             string    `json:"clinic_type"`
	VerificationStatus     string    `json:"verification_status"`
	IsVerified             bool      `json:"is_verified"`
	StaffRole              string    `json:"staff_role"`
	CanManageStaff         bool      `json:"can_manage_staff"`
	CanEditClinicInfo      bool      `json:"can_edit_clinic_info"`
	CanApproveAppointments bool      `json:"can_approve_appointments"`
	IsPrimaryContact       bool      `json:"is_primary_contact"`
}

// OnboardingSteps represents the various steps in provider onboarding
const (
	OnboardingStepAccountCreated   = "account_created"
	OnboardingStepClinicRegistered = "clinic_registered"
	OnboardingStepClinicApproved   = "clinic_approved"
	OnboardingStepCompleted        = "completed"
)
