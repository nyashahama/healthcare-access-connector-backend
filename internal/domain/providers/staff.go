package providers

import (
	"time"

	"github.com/google/uuid"
)

// ClinicStaff represents a healthcare worker
type ClinicStaff struct {
	ID                  uuid.UUID      `json:"id"`
	ClinicID            uuid.UUID      `json:"clinic_id"`
	UserID              *uuid.UUID     `json:"user_id,omitempty"` // Nullable for pending invitations
	Title               *string        `json:"title,omitempty"`   // Dr, Nurse, Sr, Mr, Ms
	FirstName           string         `json:"first_name"`
	LastName            string         `json:"last_name"`
	ProfessionalTitle   *string        `json:"professional_title,omitempty"` // General Practitioner, Registered Nurse
	Specialization      *string        `json:"specialization,omitempty"`
	WorkEmail           *string        `json:"work_email,omitempty"`
	WorkPhone           *string        `json:"work_phone,omitempty"`
	PersonalPhone       *string        `json:"personal_phone,omitempty"`
	HPCSNumber          *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications      []string       `json:"qualifications,omitempty"`
	YearsExperience     *int           `json:"years_experience,omitempty"`
	Bio                 *string        `json:"bio,omitempty"`
	StaffRole           string         `json:"staff_role"` // owner, admin, manager, doctor, nurse, receptionist
	Department          *string        `json:"department,omitempty"`
	IsPrimaryContact    bool           `json:"is_primary_contact"`

	//  Invitation fields
	InvitationToken   *string    `json:"invitation_token,omitempty"`
	InvitationStatus  *string    `json:"invitation_status,omitempty"` // pending, accepted, declined, expired
	InvitedBy         *uuid.UUID `json:"invited_by,omitempty"`
	InvitedAt         *time.Time `json:"invited_at,omitempty"`
	InvitationExpires *time.Time `json:"invitation_expires,omitempty"`

	//  Permission fields
	Permissions            map[string]any `json:"permissions,omitempty"`
	CanManageStaff         bool           `json:"can_manage_staff"`
	CanApproveAppointments bool           `json:"can_approve_appointments"`
	CanEditClinicInfo      bool           `json:"can_edit_clinic_info"`

	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status"` // active, on_leave, terminated, invited
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

// StaffInvitation represents the data needed to invite a staff member
type StaffInvitation struct {
	ClinicID               uuid.UUID `json:"clinic_id"`
	WorkEmail              string    `json:"work_email"`
	FirstName              string    `json:"first_name"`
	LastName               string    `json:"last_name"`
	StaffRole              string    `json:"staff_role"`
	ProfessionalTitle      *string   `json:"professional_title,omitempty"`
	InvitationToken        string    `json:"invitation_token"`
	InvitedBy              uuid.UUID `json:"invited_by"`
	InvitationExpires      time.Time `json:"invitation_expires"`
	CanManageStaff         bool      `json:"can_manage_staff"`
	CanApproveAppointments bool      `json:"can_approve_appointments"`
	CanEditClinicInfo      bool      `json:"can_edit_clinic_info"`
}

// StaffInvitationDetails represents invitation with clinic information
type StaffInvitationDetails struct {
	StaffInvitation
	ClinicName   string  `json:"clinic_name"`
	City         *string `json:"city,omitempty"`
	Province     *string `json:"province,omitempty"`
	InviterEmail *string `json:"inviter_email,omitempty"`
	InviterPhone *string `json:"inviter_phone,omitempty"`
}

// StaffPermissions represents the permissions a staff member has
type StaffPermissions struct {
	CanManageStaff         bool           `json:"can_manage_staff"`
	CanApproveAppointments bool           `json:"can_approve_appointments"`
	CanEditClinicInfo      bool           `json:"can_edit_clinic_info"`
	CustomPermissions      map[string]any `json:"custom_permissions,omitempty"`
}

// InvitationStatus constants
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusDeclined = "declined"
	InvitationStatusExpired  = "expired"
)

// EmploymentStatus constants
const (
	EmploymentStatusActive     = "active"
	EmploymentStatusOnLeave    = "on_leave"
	EmploymentStatusTerminated = "terminated"
	EmploymentStatusInvited    = "invited"
)

// StaffRole constants
const (
	StaffRoleOwner        = "owner"
	StaffRoleAdmin        = "admin"
	StaffRoleManager      = "manager"
	StaffRoleDoctor       = "doctor"
	StaffRoleNurse        = "nurse"
	StaffRoleReceptionist = "receptionist"
)

// ============================================
// EXISTING SUPPORTING TYPES
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
