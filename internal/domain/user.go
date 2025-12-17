// Package domain
package domain

import (
	"time"

	"github.com/docker/distribution/uuid"
)

// User represents a system user with role-based access
type User struct {
	ID                   uuid.UUID  `json:"id"`
	Email                *string    `json:"email,omitempty"`
	Phone                *string    `json:"phone,omitempty"`
	Role                 string     `json:"role"`   // patient, caregiver, provider_staff, clinic_admin, system_admin, ngo_partner
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
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// PatientProfile represents detailed patient information
type PatientProfile struct {
	ID                           uuid.UUID  `json:"id"`
	UserID                       uuid.UUID  `json:"user_id"`
	FirstName                    string     `json:"first_name"`
	LastName                     string     `json:"last_name"`
	PreferredName                *string    `json:"preferred_name,omitempty"`
	DateOfBirth                  *time.Time `json:"date_of_birth,omitempty"`
	Gender                       *string    `json:"gender,omitempty"`
	PreferredGenderPronouns      *string    `json:"preferred_gender_pronouns,omitempty"`
	PrimaryAddress               *string    `json:"primary_address,omitempty"`
	City                         *string    `json:"city,omitempty"`
	Province                     *string    `json:"province,omitempty"`
	PostalCode                   *string    `json:"postal_code,omitempty"`
	Country                      string     `json:"country"`
	LanguagePreferences          []string   `json:"language_preferences"`
	HomeLanguage                 *string    `json:"home_language,omitempty"`
	RequiresInterpreter          bool       `json:"requires_interpreter"`
	PreferredCommunicationMethod string     `json:"preferred_communication_method"` // sms, email, whatsapp, call
	MedicalAidNumber             *string    `json:"medical_aid_number,omitempty"`
	MedicalAidProvider           *string    `json:"medical_aid_provider,omitempty"`
	HasMedicalAid                bool       `json:"has_medical_aid"`
	NationalIDNumber             *string    `json:"national_id_number,omitempty"`
	EmploymentStatus             *string    `json:"employment_status,omitempty"`
	EducationLevel               *string    `json:"education_level,omitempty"`
	HouseholdIncomeRange         *string    `json:"household_income_range,omitempty"`
	ProfilePictureURL            *string    `json:"profile_picture_url,omitempty"`
	Timezone                     string     `json:"timezone"`
	LastProfileUpdate            *time.Time `json:"last_profile_update,omitempty"`
	ReferredBy                   *uuid.UUID `json:"referred_by,omitempty"`
	ReferralCode                 *string    `json:"referral_code,omitempty"`
	AcceptsMarketingEmails       bool       `json:"accepts_marketing_emails"`
	CreatedAt                    time.Time  `json:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at"`
}
