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

// PatientMedicalInfo represents patient medical information
type PatientMedicalInfo struct {
	ID                     uuid.UUID  `json:"id"`
	PatientID              uuid.UUID  `json:"patient_id"`
	BloodType              *string    `json:"blood_type,omitempty"`
	BloodTypeLastTested    *time.Time `json:"blood_type_last_tested,omitempty"`
	HeightCm               *float64   `json:"height_cm,omitempty"`
	WeightKg               *float64   `json:"weight_kg,omitempty"`
	BMI                    *float64   `json:"bmi,omitempty"`
	LastMeasuredDate       *time.Time `json:"last_measured_date,omitempty"`
	OverallHealthStatus    *string    `json:"overall_health_status,omitempty"`
	HealthSummary          *string    `json:"health_summary,omitempty"`
	PrimaryCarePhysician   *string    `json:"primary_care_physician,omitempty"`
	PrimaryClinicID        *uuid.UUID `json:"primary_clinic_id,omitempty"`
	OrganDonor             bool       `json:"organ_donor"`
	AdvanceDirectiveExists bool       `json:"advance_directive_exists"`
	AdvanceDirectiveURL    *string    `json:"advance_directive_url,omitempty"`
	DNRStatus              bool       `json:"dnr_status"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// PatientAllergy represents a patient allergy
type PatientAllergy struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	AllergyName         string     `json:"allergy_name"`
	Severity            string     `json:"severity"` // mild, moderate, severe, life_threatening
	ReactionDescription *string    `json:"reaction_description,omitempty"`
	FirstIdentifiedDate *time.Time `json:"first_identified_date,omitempty"`
	LastOccurrenceDate  *time.Time `json:"last_occurrence_date,omitempty"`
	Status              string     `json:"status"` // active, resolved, inactive
	Notes               *string    `json:"notes,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// PatientMedication represents a patient medication
type PatientMedication struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	MedicationName      string     `json:"medication_name"`
	GenericName         *string    `json:"generic_name,omitempty"`
	Dosage              *string    `json:"dosage,omitempty"`
	Frequency           *string    `json:"frequency,omitempty"`
	Route               *string    `json:"route,omitempty"`
	PrescribingDoctor   *string    `json:"prescribing_doctor,omitempty"`
	PharmacyName        *string    `json:"pharmacy_name,omitempty"`
	PrescriptionDate    *time.Time `json:"prescription_date,omitempty"`
	StartDate           *time.Time `json:"start_date,omitempty"`
	EndDate             *time.Time `json:"end_date,omitempty"`
	ReasonForMedication *string    `json:"reason_for_medication,omitempty"`
	Status              string     `json:"status"` // active, completed, discontinued
	SideEffects         *string    `json:"side_effects,omitempty"`
	Instructions        *string    `json:"instructions,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// PatientCondition represents a patient medical condition
type PatientCondition struct {
	ID              uuid.UUID  `json:"id"`
	PatientID       uuid.UUID  `json:"patient_id"`
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"` // chronic, acute, genetic, mental_health
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"` // mild, moderate, severe
	Status          string     `json:"status"`             // active, resolved, remission, managed
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
