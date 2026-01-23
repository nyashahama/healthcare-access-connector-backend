package patients

import (
	"time"

	"github.com/google/uuid"
)

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

// AdvancedSearchParams encapsulates all search parameters
type AdvancedSearchParams struct {
	Query                  *string
	Province               *string
	City                   *string
	HasMedicalAid          *bool
	Gender                 *string
	CommunicationMethod    *string
	EmploymentStatus       *string
	MedicalAidProvider     *string
	RequiresInterpreter    *bool
	AcceptsMarketingEmails *bool
	Limit                  int
	Offset                 int
}

// PatientDemographicsSummary provides aggregated patient data
type PatientDemographicsSummary struct {
	TotalPatients        int64   `json:"total_patients"`
	ProvincesCovered     int64   `json:"provinces_covered"`
	CitiesCovered        int64   `json:"cities_covered"`
	WithMedicalAid       int64   `json:"with_medical_aid"`
	RequiringInterpreter int64   `json:"requiring_interpreter"`
	MarketingOptIn       int64   `json:"marketing_opt_in"`
	AverageAge           float64 `json:"average_age"`
}
