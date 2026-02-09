package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// CreateStaffRequest represents a request to create a staff member
type CreateStaffRequest struct {
	ClinicID            uuid.UUID      `json:"clinic_id"`
	UserID              *uuid.UUID     `json:"user_id,omitempty"`
	Title               *string        `json:"title,omitempty"`
	FirstName           string         `json:"first_name"`
	LastName            string         `json:"last_name"`
	ProfessionalTitle   *string        `json:"professional_title,omitempty"`
	Specialization      *string        `json:"specialization,omitempty"`
	WorkEmail           *string        `json:"work_email,omitempty"`
	WorkPhone           *string        `json:"work_phone,omitempty"`
	PersonalPhone       *string        `json:"personal_phone,omitempty"`
	HPCSNumber          *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications      []string       `json:"qualifications,omitempty"`
	YearsExperience     *int           `json:"years_experience,omitempty"`
	Bio                 *string        `json:"bio,omitempty"`
	StaffRole           string         `json:"staff_role"`
	Department          *string        `json:"department,omitempty"`
	IsPrimaryContact    bool           `json:"is_primary_contact"`

	// Permission fields
	Permissions            map[string]any `json:"permissions,omitempty"`
	CanManageStaff         bool           `json:"can_manage_staff"`
	CanApproveAppointments bool           `json:"can_approve_appointments"`
	CanEditClinicInfo      bool           `json:"can_edit_clinic_info"`

	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status"`
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
}

// UpdateStaffRequest represents a request to update a staff member
type UpdateStaffRequest struct {
	Title               *string        `json:"title,omitempty"`
	FirstName           string         `json:"first_name"`
	LastName            string         `json:"last_name"`
	ProfessionalTitle   *string        `json:"professional_title,omitempty"`
	Specialization      *string        `json:"specialization,omitempty"`
	WorkEmail           *string        `json:"work_email,omitempty"`
	WorkPhone           *string        `json:"work_phone,omitempty"`
	PersonalPhone       *string        `json:"personal_phone,omitempty"`
	HPCSNumber          *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications      []string       `json:"qualifications,omitempty"`
	YearsExperience     *int           `json:"years_experience,omitempty"`
	Bio                 *string        `json:"bio,omitempty"`
	StaffRole           string         `json:"staff_role"`
	Department          *string        `json:"department,omitempty"`
	IsPrimaryContact    bool           `json:"is_primary_contact"`

	// Permission fields
	Permissions            map[string]any `json:"permissions,omitempty"`
	CanManageStaff         bool           `json:"can_manage_staff"`
	CanApproveAppointments bool           `json:"can_approve_appointments"`
	CanEditClinicInfo      bool           `json:"can_edit_clinic_info"`

	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status"`
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
}

// InviteStaffRequest represents a request to invite a staff member
type InviteStaffRequest struct {
	WorkEmail              string  `json:"work_email"`
	FirstName              string  `json:"first_name"`
	LastName               string  `json:"last_name"`
	StaffRole              string  `json:"staff_role"`
	ProfessionalTitle      *string `json:"professional_title,omitempty"`
	CanManageStaff         bool    `json:"can_manage_staff"`
	CanApproveAppointments bool    `json:"can_approve_appointments"`
	CanEditClinicInfo      bool    `json:"can_edit_clinic_info"`
}

// AcceptInvitationRequest represents a request to accept a staff invitation
type AcceptInvitationRequest struct {
	InvitationToken string     `json:"invitation_token"`
	UserID          uuid.UUID  `json:"user_id"`
	Title           *string    `json:"title,omitempty"`
	PersonalPhone   *string    `json:"personal_phone,omitempty"`
	Bio             *string    `json:"bio,omitempty"`
	StartDate       *time.Time `json:"start_date,omitempty"`
}

// StaffResponse represents a staff member in responses
type StaffResponse struct {
	ID                  uuid.UUID      `json:"id"`
	ClinicID            uuid.UUID      `json:"clinic_id"`
	UserID              *uuid.UUID     `json:"user_id,omitempty"`
	Title               *string        `json:"title,omitempty"`
	FirstName           string         `json:"first_name"`
	LastName            string         `json:"last_name"`
	ProfessionalTitle   *string        `json:"professional_title,omitempty"`
	Specialization      *string        `json:"specialization,omitempty"`
	WorkEmail           *string        `json:"work_email,omitempty"`
	WorkPhone           *string        `json:"work_phone,omitempty"`
	PersonalPhone       *string        `json:"personal_phone,omitempty"`
	HPCSNumber          *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications      []string       `json:"qualifications,omitempty"`
	YearsExperience     *int           `json:"years_experience,omitempty"`
	Bio                 *string        `json:"bio,omitempty"`
	StaffRole           string         `json:"staff_role"`
	Department          *string        `json:"department,omitempty"`
	IsPrimaryContact    bool           `json:"is_primary_contact"`

	// Invitation fields
	InvitationToken   *string    `json:"invitation_token,omitempty"`
	InvitationStatus  *string    `json:"invitation_status,omitempty"`
	InvitedBy         *uuid.UUID `json:"invited_by,omitempty"`
	InvitedAt         *time.Time `json:"invited_at,omitempty"`
	InvitationExpires *time.Time `json:"invitation_expires,omitempty"`

	// Permission fields
	Permissions            map[string]any `json:"permissions,omitempty"`
	CanManageStaff         bool           `json:"can_manage_staff"`
	CanApproveAppointments bool           `json:"can_approve_appointments"`
	CanEditClinicInfo      bool           `json:"can_edit_clinic_info"`

	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status"`
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

// StaffInvitationResponse represents a staff invitation with clinic details
type StaffInvitationResponse struct {
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

	// Clinic information
	ClinicName   string  `json:"clinic_name"`
	City         *string `json:"city,omitempty"`
	Province     *string `json:"province,omitempty"`
	InviterEmail *string `json:"inviter_email,omitempty"`
	InviterPhone *string `json:"inviter_phone,omitempty"`
}

// UpdatePermissionsRequest represents a request to update staff permissions
type UpdatePermissionsRequest struct {
	CanManageStaff         bool           `json:"can_manage_staff"`
	CanApproveAppointments bool           `json:"can_approve_appointments"`
	CanEditClinicInfo      bool           `json:"can_edit_clinic_info"`
	CustomPermissions      map[string]any `json:"custom_permissions,omitempty"`
}

// StaffListResponse represents a list of staff members
type StaffListResponse struct {
	Staff  []StaffResponse `json:"staff"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit,omitempty"`
	Offset int             `json:"offset,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

// ToStaffResponse converts domain ClinicStaff to response DTO
func ToStaffResponse(staff providers.ClinicStaff) StaffResponse {
	return StaffResponse{
		ID:                     staff.ID,
		ClinicID:               staff.ClinicID,
		UserID:                 staff.UserID,
		Title:                  staff.Title,
		FirstName:              staff.FirstName,
		LastName:               staff.LastName,
		ProfessionalTitle:      staff.ProfessionalTitle,
		Specialization:         staff.Specialization,
		WorkEmail:              staff.WorkEmail,
		WorkPhone:              staff.WorkPhone,
		PersonalPhone:          staff.PersonalPhone,
		HPCSNumber:             staff.HPCSNumber,
		OtherLicenseNumbers:    staff.OtherLicenseNumbers,
		Qualifications:         staff.Qualifications,
		YearsExperience:        staff.YearsExperience,
		Bio:                    staff.Bio,
		StaffRole:              staff.StaffRole,
		Department:             staff.Department,
		IsPrimaryContact:       staff.IsPrimaryContact,
		InvitationToken:        staff.InvitationToken,
		InvitationStatus:       staff.InvitationStatus,
		InvitedBy:              staff.InvitedBy,
		InvitedAt:              staff.InvitedAt,
		InvitationExpires:      staff.InvitationExpires,
		Permissions:            staff.Permissions,
		CanManageStaff:         staff.CanManageStaff,
		CanApproveAppointments: staff.CanApproveAppointments,
		CanEditClinicInfo:      staff.CanEditClinicInfo,
		WorkingHours:           staff.WorkingHours,
		AvailableDays:          staff.AvailableDays,
		IsAcceptingNewPatients: staff.IsAcceptingNewPatients,
		EmploymentStatus:       staff.EmploymentStatus,
		StartDate:              staff.StartDate,
		EndDate:                staff.EndDate,
		ProfilePictureURL:      staff.ProfilePictureURL,
		LanguagesSpoken:        staff.LanguagesSpoken,
		CreatedAt:              staff.CreatedAt,
		UpdatedAt:              staff.UpdatedAt,
	}
}

// ToStaffInvitationResponse converts domain StaffInvitationDetails to response DTO
func ToStaffInvitationResponse(details providers.StaffInvitationDetails) StaffInvitationResponse {
	return StaffInvitationResponse{
		ClinicID:               details.ClinicID,
		WorkEmail:              details.WorkEmail,
		FirstName:              details.FirstName,
		LastName:               details.LastName,
		StaffRole:              details.StaffRole,
		ProfessionalTitle:      details.ProfessionalTitle,
		InvitationToken:        details.InvitationToken,
		InvitedBy:              details.InvitedBy,
		InvitationExpires:      details.InvitationExpires,
		CanManageStaff:         details.CanManageStaff,
		CanApproveAppointments: details.CanApproveAppointments,
		CanEditClinicInfo:      details.CanEditClinicInfo,
		ClinicName:             details.ClinicName,
		City:                   details.City,
		Province:               details.Province,
		InviterEmail:           details.InviterEmail,
		InviterPhone:           details.InviterPhone,
	}
}

// ToDomainStaff converts request DTO to domain model
func ToDomainStaff(req CreateStaffRequest) providers.ClinicStaff {
	return providers.ClinicStaff{
		ClinicID:               req.ClinicID,
		UserID:                 req.UserID,
		Title:                  req.Title,
		FirstName:              req.FirstName,
		LastName:               req.LastName,
		ProfessionalTitle:      req.ProfessionalTitle,
		Specialization:         req.Specialization,
		WorkEmail:              req.WorkEmail,
		WorkPhone:              req.WorkPhone,
		PersonalPhone:          req.PersonalPhone,
		HPCSNumber:             req.HPCSNumber,
		OtherLicenseNumbers:    req.OtherLicenseNumbers,
		Qualifications:         req.Qualifications,
		YearsExperience:        req.YearsExperience,
		Bio:                    req.Bio,
		StaffRole:              req.StaffRole,
		Department:             req.Department,
		IsPrimaryContact:       req.IsPrimaryContact,
		Permissions:            req.Permissions,
		CanManageStaff:         req.CanManageStaff,
		CanApproveAppointments: req.CanApproveAppointments,
		CanEditClinicInfo:      req.CanEditClinicInfo,
		WorkingHours:           req.WorkingHours,
		AvailableDays:          req.AvailableDays,
		IsAcceptingNewPatients: req.IsAcceptingNewPatients,
		EmploymentStatus:       req.EmploymentStatus,
		StartDate:              req.StartDate,
		EndDate:                req.EndDate,
		ProfilePictureURL:      req.ProfilePictureURL,
		LanguagesSpoken:        req.LanguagesSpoken,
	}
}

// UpdateToDomainStaff updates existing domain model with request data
func UpdateToDomainStaff(existing providers.ClinicStaff, req UpdateStaffRequest) providers.ClinicStaff {
	existing.Title = req.Title
	existing.FirstName = req.FirstName
	existing.LastName = req.LastName
	existing.ProfessionalTitle = req.ProfessionalTitle
	existing.Specialization = req.Specialization
	existing.WorkEmail = req.WorkEmail
	existing.WorkPhone = req.WorkPhone
	existing.PersonalPhone = req.PersonalPhone
	existing.HPCSNumber = req.HPCSNumber
	existing.OtherLicenseNumbers = req.OtherLicenseNumbers
	if len(req.Qualifications) > 0 {
		existing.Qualifications = req.Qualifications
	}
	existing.YearsExperience = req.YearsExperience
	existing.Bio = req.Bio
	existing.StaffRole = req.StaffRole
	existing.Department = req.Department
	existing.IsPrimaryContact = req.IsPrimaryContact
	existing.Permissions = req.Permissions
	existing.CanManageStaff = req.CanManageStaff
	existing.CanApproveAppointments = req.CanApproveAppointments
	existing.CanEditClinicInfo = req.CanEditClinicInfo
	existing.WorkingHours = req.WorkingHours
	if len(req.AvailableDays) > 0 {
		existing.AvailableDays = req.AvailableDays
	}
	existing.IsAcceptingNewPatients = req.IsAcceptingNewPatients
	existing.EmploymentStatus = req.EmploymentStatus
	existing.StartDate = req.StartDate
	existing.EndDate = req.EndDate
	existing.ProfilePictureURL = req.ProfilePictureURL
	if len(req.LanguagesSpoken) > 0 {
		existing.LanguagesSpoken = req.LanguagesSpoken
	}
	return existing
}

// ToStaffInvitation converts invite request to domain StaffInvitation
func ToStaffInvitation(clinicID uuid.UUID, invitedBy uuid.UUID, req InviteStaffRequest, token string, expiresAt time.Time) providers.StaffInvitation {
	return providers.StaffInvitation{
		ClinicID:               clinicID,
		WorkEmail:              req.WorkEmail,
		FirstName:              req.FirstName,
		LastName:               req.LastName,
		StaffRole:              req.StaffRole,
		ProfessionalTitle:      req.ProfessionalTitle,
		InvitationToken:        token,
		InvitedBy:              invitedBy,
		InvitationExpires:      expiresAt,
		CanManageStaff:         req.CanManageStaff,
		CanApproveAppointments: req.CanApproveAppointments,
		CanEditClinicInfo:      req.CanEditClinicInfo,
	}
}
