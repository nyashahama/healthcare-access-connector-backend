package providers

import (
	"time"

	"github.com/google/uuid"
)

// ClinicStaff represents a healthcare worker
type ClinicStaff struct {
	ID                     uuid.UUID      `json:"id"`
	ClinicID               uuid.UUID      `json:"clinic_id"`
	UserID                 uuid.UUID      `json:"user_id"`
	Title                  *string        `json:"title,omitempty"` // Dr, Nurse, Sr, Mr, Ms
	FirstName              string         `json:"first_name"`
	LastName               string         `json:"last_name"`
	ProfessionalTitle      *string        `json:"professional_title,omitempty"` // General Practitioner, Registered Nurse
	Specialization         *string        `json:"specialization,omitempty"`
	WorkEmail              *string        `json:"work_email,omitempty"`
	WorkPhone              *string        `json:"work_phone,omitempty"`
	PersonalPhone          *string        `json:"personal_phone,omitempty"`
	HPCSNumber             *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers    map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications         []string       `json:"qualifications,omitempty"`
	YearsExperience        *int           `json:"years_experience,omitempty"`
	Bio                    *string        `json:"bio,omitempty"`
	StaffRole              string         `json:"staff_role"` // doctor, nurse, administrator, receptionist, manager
	Department             *string        `json:"department,omitempty"`
	IsPrimaryContact       bool           `json:"is_primary_contact"`
	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status"` // active, on_leave, terminated
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

// ============================================
// SUPPORTING TYPES - STAFF REPOSITORY
// ============================================

type StaffProfessionalInfo struct {
	ProfessionalTitle *string
	Specialization    *string
	Qualifications    []string
	YearsExperience   *int
	Bio               *string
}

type StaffLicenses struct {
	HPCSNumber          *string
	OtherLicenseNumbers map[string]any
}

type StaffContact struct {
	WorkEmail     *string
	WorkPhone     *string
	PersonalPhone *string
}

type StaffProfile struct {
	Bio               *string
	ProfilePictureURL *string
	LanguagesSpoken   []string
}

type StaffWorkingHours struct {
	ID            uuid.UUID
	FirstName     string
	LastName      string
	WorkingHours  map[string]any
	AvailableDays []string
}

type StaffCredentialRenewal struct {
	ID             uuid.UUID
	ClinicID       uuid.UUID
	FirstName      string
	LastName       string
	WorkEmail      *string
	CredentialType string
	ExpiryDate     *time.Time
}

type StaffStatistics struct {
	ID                     uuid.UUID
	FullName               string
	ProfessionalTitle      *string
	Specialization         *string
	YearsExperience        *int
	EmploymentStatus       string
	IsAcceptingNewPatients bool
	CreatedAt              time.Time
}

type StaffMetrics struct {
	TotalStaff             int64
	ActiveStaff            int64
	OnLeaveStaff           int64
	TerminatedStaff        int64
	DoctorCount            int64
	NurseCount             int64
	AdminCount             int64
	AcceptingPatientsCount int64
	AverageExperience      *float64
}

type StaffRoleDistribution struct {
	StaffRole         string
	Count             int64
	AverageExperience *float64
}

type StaffDemographics struct {
	TotalStaff             int64
	UniqueSpecializations  int64
	UniqueRoles            int64
	AverageLanguagesSpoken *float64
}

type StaffLanguageInfo struct {
	ID                uuid.UUID
	FirstName         string
	LastName          string
	ProfessionalTitle *string
	LanguagesSpoken   []string
	LanguageCount     int
}
