package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreatePatientProfileRequest represents a request to create a patient profile
type CreatePatientProfileRequest struct {
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
	LanguagePreferences          []string   `json:"language_preferences,omitempty"`
	HomeLanguage                 *string    `json:"home_language,omitempty"`
	RequiresInterpreter          bool       `json:"requires_interpreter"`
	PreferredCommunicationMethod string     `json:"preferred_communication_method"`
	MedicalAidNumber             *string    `json:"medical_aid_number,omitempty"`
	MedicalAidProvider           *string    `json:"medical_aid_provider,omitempty"`
	HasMedicalAid                bool       `json:"has_medical_aid"`
	NationalIDNumber             *string    `json:"national_id_number,omitempty"`
	EmploymentStatus             *string    `json:"employment_status,omitempty"`
	EducationLevel               *string    `json:"education_level,omitempty"`
	HouseholdIncomeRange         *string    `json:"household_income_range,omitempty"`
	ProfilePictureURL            *string    `json:"profile_picture_url,omitempty"`
	Timezone                     string     `json:"timezone"`
	AcceptsMarketingEmails       bool       `json:"accepts_marketing_emails"`
}

// UpdatePatientProfileRequest represents a request to update a patient profile
type UpdatePatientProfileRequest struct {
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
	LanguagePreferences          []string   `json:"language_preferences,omitempty"`
	HomeLanguage                 *string    `json:"home_language,omitempty"`
	RequiresInterpreter          bool       `json:"requires_interpreter"`
	PreferredCommunicationMethod string     `json:"preferred_communication_method"`
	MedicalAidNumber             *string    `json:"medical_aid_number,omitempty"`
	MedicalAidProvider           *string    `json:"medical_aid_provider,omitempty"`
	HasMedicalAid                bool       `json:"has_medical_aid"`
	NationalIDNumber             *string    `json:"national_id_number,omitempty"`
	EmploymentStatus             *string    `json:"employment_status,omitempty"`
	EducationLevel               *string    `json:"education_level,omitempty"`
	HouseholdIncomeRange         *string    `json:"household_income_range,omitempty"`
	ProfilePictureURL            *string    `json:"profile_picture_url,omitempty"`
	Timezone                     string     `json:"timezone"`
	AcceptsMarketingEmails       bool       `json:"accepts_marketing_emails"`
}

// PatientProfileResponse represents a patient profile in responses
type PatientProfileResponse struct {
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
	PreferredCommunicationMethod string     `json:"preferred_communication_method"`
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
	AcceptsMarketingEmails       bool       `json:"accepts_marketing_emails"`
	CreatedAt                    time.Time  `json:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at"`
}

// SearchPatientsRequest represents a search request
type SearchPatientsRequest struct {
	Query                  *string `json:"query,omitempty"`
	Province               *string `json:"province,omitempty"`
	City                   *string `json:"city,omitempty"`
	HasMedicalAid          *bool   `json:"has_medical_aid,omitempty"`
	Gender                 *string `json:"gender,omitempty"`
	CommunicationMethod    *string `json:"communication_method,omitempty"`
	EmploymentStatus       *string `json:"employment_status,omitempty"`
	MedicalAidProvider     *string `json:"medical_aid_provider,omitempty"`
	RequiresInterpreter    *bool   `json:"requires_interpreter,omitempty"`
	AcceptsMarketingEmails *bool   `json:"accepts_marketing_emails,omitempty"`
	Limit                  int     `json:"limit,omitempty"`
	Offset                 int     `json:"offset,omitempty"`
}

// SearchPatientsResponse represents a search response
type SearchPatientsResponse struct {
	Patients []PatientProfileResponse `json:"patients"`
	Count    int                      `json:"count"`
	Total    int                      `json:"total"`
	Limit    int                      `json:"limit"`
	Offset   int                      `json:"offset"`
}

// DemographicsResponse represents demographics summary response
type DemographicsResponse struct {
	Summary patients.PatientDemographicsSummary `json:"summary"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

// ToPatientProfileResponse converts domain PatientProfile to response DTO
func ToPatientProfileResponse(profile patients.PatientProfile) PatientProfileResponse {
	return PatientProfileResponse{
		ID:                           profile.ID,
		UserID:                       profile.UserID,
		FirstName:                    profile.FirstName,
		LastName:                     profile.LastName,
		PreferredName:                profile.PreferredName,
		DateOfBirth:                  profile.DateOfBirth,
		Gender:                       profile.Gender,
		PreferredGenderPronouns:      profile.PreferredGenderPronouns,
		PrimaryAddress:               profile.PrimaryAddress,
		City:                         profile.City,
		Province:                     profile.Province,
		PostalCode:                   profile.PostalCode,
		Country:                      profile.Country,
		LanguagePreferences:          profile.LanguagePreferences,
		HomeLanguage:                 profile.HomeLanguage,
		RequiresInterpreter:          profile.RequiresInterpreter,
		PreferredCommunicationMethod: profile.PreferredCommunicationMethod,
		MedicalAidNumber:             profile.MedicalAidNumber,
		MedicalAidProvider:           profile.MedicalAidProvider,
		HasMedicalAid:                profile.HasMedicalAid,
		NationalIDNumber:             profile.NationalIDNumber,
		EmploymentStatus:             profile.EmploymentStatus,
		EducationLevel:               profile.EducationLevel,
		HouseholdIncomeRange:         profile.HouseholdIncomeRange,
		ProfilePictureURL:            profile.ProfilePictureURL,
		Timezone:                     profile.Timezone,
		LastProfileUpdate:            profile.LastProfileUpdate,
		AcceptsMarketingEmails:       profile.AcceptsMarketingEmails,
		CreatedAt:                    profile.CreatedAt,
		UpdatedAt:                    profile.UpdatedAt,
	}
}

// ToDomainPatientProfile converts request DTO to domain model
func ToDomainPatientProfile(req CreatePatientProfileRequest) patients.PatientProfile {
	return patients.PatientProfile{
		UserID:                       req.UserID,
		FirstName:                    req.FirstName,
		LastName:                     req.LastName,
		PreferredName:                req.PreferredName,
		DateOfBirth:                  req.DateOfBirth,
		Gender:                       req.Gender,
		PreferredGenderPronouns:      req.PreferredGenderPronouns,
		PrimaryAddress:               req.PrimaryAddress,
		City:                         req.City,
		Province:                     req.Province,
		PostalCode:                   req.PostalCode,
		Country:                      req.Country,
		LanguagePreferences:          req.LanguagePreferences,
		HomeLanguage:                 req.HomeLanguage,
		RequiresInterpreter:          req.RequiresInterpreter,
		PreferredCommunicationMethod: req.PreferredCommunicationMethod,
		MedicalAidNumber:             req.MedicalAidNumber,
		MedicalAidProvider:           req.MedicalAidProvider,
		HasMedicalAid:                req.HasMedicalAid,
		NationalIDNumber:             req.NationalIDNumber,
		EmploymentStatus:             req.EmploymentStatus,
		EducationLevel:               req.EducationLevel,
		HouseholdIncomeRange:         req.HouseholdIncomeRange,
		ProfilePictureURL:            req.ProfilePictureURL,
		Timezone:                     req.Timezone,
		AcceptsMarketingEmails:       req.AcceptsMarketingEmails,
	}
}

// UpdateToDomainPatientProfile updates existing domain model with request data
func UpdateToDomainPatientProfile(existing patients.PatientProfile, req UpdatePatientProfileRequest) patients.PatientProfile {
	existing.FirstName = req.FirstName
	existing.LastName = req.LastName
	existing.PreferredName = req.PreferredName
	existing.DateOfBirth = req.DateOfBirth
	existing.Gender = req.Gender
	existing.PreferredGenderPronouns = req.PreferredGenderPronouns
	existing.PrimaryAddress = req.PrimaryAddress
	existing.City = req.City
	existing.Province = req.Province
	existing.PostalCode = req.PostalCode
	existing.Country = req.Country
	if len(req.LanguagePreferences) > 0 {
		existing.LanguagePreferences = req.LanguagePreferences
	}
	existing.HomeLanguage = req.HomeLanguage
	existing.RequiresInterpreter = req.RequiresInterpreter
	existing.PreferredCommunicationMethod = req.PreferredCommunicationMethod
	existing.MedicalAidNumber = req.MedicalAidNumber
	existing.MedicalAidProvider = req.MedicalAidProvider
	existing.HasMedicalAid = req.HasMedicalAid
	existing.NationalIDNumber = req.NationalIDNumber
	existing.EmploymentStatus = req.EmploymentStatus
	existing.EducationLevel = req.EducationLevel
	existing.HouseholdIncomeRange = req.HouseholdIncomeRange
	existing.ProfilePictureURL = req.ProfilePictureURL
	existing.Timezone = req.Timezone
	existing.AcceptsMarketingEmails = req.AcceptsMarketingEmails
	return existing
}
