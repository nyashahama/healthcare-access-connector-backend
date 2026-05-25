package admin

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
)

// CreateSystemAdminRequest represents the request to create a system admin
type CreateSystemAdminRequest struct {
	UserID           uuid.UUID   `json:"user_id"`
	AdminLevel       string      `json:"admin_level"`
	AssignedRegions  []string    `json:"assigned_regions,omitempty"`
	Department       *string     `json:"department,omitempty"`
	Permissions      interface{} `json:"permissions,omitempty"`
	CanManageUsers   bool        `json:"can_manage_users"`
	CanManageClinics bool        `json:"can_manage_clinics"`
	CanManageContent bool        `json:"can_manage_content"`
	CanViewAnalytics bool        `json:"can_view_analytics"`
	CanManageSystem  bool        `json:"can_manage_system"`
	WorkPhone        *string     `json:"work_phone,omitempty"`
	Extension        *string     `json:"extension,omitempty"`
}

// ToDomain converts CreateSystemAdminRequest to domain model
func (r CreateSystemAdminRequest) ToDomain() admin.SystemAdmin {
	return admin.SystemAdmin{
		UserID:           r.UserID,
		AdminLevel:       r.AdminLevel,
		AssignedRegions:  r.AssignedRegions,
		Department:       r.Department,
		Permissions:      r.Permissions,
		CanManageUsers:   r.CanManageUsers,
		CanManageClinics: r.CanManageClinics,
		CanManageContent: r.CanManageContent,
		CanViewAnalytics: r.CanViewAnalytics,
		CanManageSystem:  r.CanManageSystem,
		WorkPhone:        r.WorkPhone,
		Extension:        r.Extension,
	}
}

// UpdateSystemAdminRequest represents the request to update a system admin
type UpdateSystemAdminRequest struct {
	AdminLevel       *string     `json:"admin_level,omitempty"`
	AssignedRegions  []string    `json:"assigned_regions,omitempty"`
	Department       *string     `json:"department,omitempty"`
	Permissions      interface{} `json:"permissions,omitempty"`
	CanManageUsers   *bool       `json:"can_manage_users,omitempty"`
	CanManageClinics *bool       `json:"can_manage_clinics,omitempty"`
	CanManageContent *bool       `json:"can_manage_content,omitempty"`
	CanViewAnalytics *bool       `json:"can_view_analytics,omitempty"`
	CanManageSystem  *bool       `json:"can_manage_system,omitempty"`
	WorkPhone        *string     `json:"work_phone,omitempty"`
	Extension        *string     `json:"extension,omitempty"`
}

// ToDomain converts UpdateSystemAdminRequest to domain model
func (r UpdateSystemAdminRequest) ToDomain() admin.SystemAdmin {
	sysAdmin := admin.SystemAdmin{}

	if r.AdminLevel != nil {
		sysAdmin.AdminLevel = *r.AdminLevel
	}
	if r.AssignedRegions != nil {
		sysAdmin.AssignedRegions = r.AssignedRegions
	}
	if r.Department != nil {
		sysAdmin.Department = r.Department
	}
	if r.Permissions != nil {
		sysAdmin.Permissions = r.Permissions
	}
	if r.CanManageUsers != nil {
		sysAdmin.CanManageUsers = *r.CanManageUsers
	}
	if r.CanManageClinics != nil {
		sysAdmin.CanManageClinics = *r.CanManageClinics
	}
	if r.CanManageContent != nil {
		sysAdmin.CanManageContent = *r.CanManageContent
	}
	if r.CanViewAnalytics != nil {
		sysAdmin.CanViewAnalytics = *r.CanViewAnalytics
	}
	if r.CanManageSystem != nil {
		sysAdmin.CanManageSystem = *r.CanManageSystem
	}
	if r.WorkPhone != nil {
		sysAdmin.WorkPhone = r.WorkPhone
	}
	if r.Extension != nil {
		sysAdmin.Extension = r.Extension
	}

	return sysAdmin
}

// UpdatePermissionsRequest represents the request to update permissions
type UpdatePermissionsRequest struct {
	Permissions      interface{} `json:"permissions,omitempty"`
	CanManageUsers   bool        `json:"can_manage_users"`
	CanManageClinics bool        `json:"can_manage_clinics"`
	CanManageContent bool        `json:"can_manage_content"`
	CanViewAnalytics bool        `json:"can_view_analytics"`
	CanManageSystem  bool        `json:"can_manage_system"`
}

// ToDomain converts UpdatePermissionsRequest to domain model
func (r UpdatePermissionsRequest) ToDomain() admin.SystemAdmin {
	return admin.SystemAdmin{
		Permissions:      r.Permissions,
		CanManageUsers:   r.CanManageUsers,
		CanManageClinics: r.CanManageClinics,
		CanManageContent: r.CanManageContent,
		CanViewAnalytics: r.CanViewAnalytics,
		CanManageSystem:  r.CanManageSystem,
	}
}

// SystemAdminResponse represents the system admin response
type SystemAdminResponse struct {
	ID               uuid.UUID   `json:"id"`
	UserID           uuid.UUID   `json:"user_id"`
	AdminLevel       string      `json:"admin_level"`
	AssignedRegions  []string    `json:"assigned_regions,omitempty"`
	Department       *string     `json:"department,omitempty"`
	Permissions      interface{} `json:"permissions,omitempty"`
	CanManageUsers   bool        `json:"can_manage_users"`
	CanManageClinics bool        `json:"can_manage_clinics"`
	CanManageContent bool        `json:"can_manage_content"`
	CanViewAnalytics bool        `json:"can_view_analytics"`
	CanManageSystem  bool        `json:"can_manage_system"`
	WorkPhone        *string     `json:"work_phone,omitempty"`
	Extension        *string     `json:"extension,omitempty"`
	CreatedAt        string      `json:"created_at"`
	UpdatedAt        string      `json:"updated_at"`
}

// ToSystemAdminResponse converts domain model to response DTO
func ToSystemAdminResponse(sysAdmin admin.SystemAdmin) SystemAdminResponse {
	return SystemAdminResponse{
		ID:               sysAdmin.ID,
		UserID:           sysAdmin.UserID,
		AdminLevel:       sysAdmin.AdminLevel,
		AssignedRegions:  sysAdmin.AssignedRegions,
		Department:       sysAdmin.Department,
		Permissions:      sysAdmin.Permissions,
		CanManageUsers:   sysAdmin.CanManageUsers,
		CanManageClinics: sysAdmin.CanManageClinics,
		CanManageContent: sysAdmin.CanManageContent,
		CanViewAnalytics: sysAdmin.CanViewAnalytics,
		CanManageSystem:  sysAdmin.CanManageSystem,
		WorkPhone:        sysAdmin.WorkPhone,
		Extension:        sysAdmin.Extension,
		CreatedAt:        sysAdmin.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:        sysAdmin.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// SystemAdminFilter represents filters for listing system admins
type SystemAdminFilter struct {
	AdminLevel string
	Region     string
	Department string
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

type CreateNGOPartnerRequest struct {
	UserID                uuid.UUID   `json:"user_id"`
	OrganizationName      string      `json:"organization_name"`
	OrganizationType      *string     `json:"organization_type,omitempty"`
	RegistrationNumber    *string     `json:"registration_number,omitempty"`
	TaxID                 *string     `json:"tax_id,omitempty"`
	OrganizationAddress   *string     `json:"organization_address,omitempty"`
	OrganizationPhone     *string     `json:"organization_phone,omitempty"`
	OrganizationEmail     *string     `json:"organization_email,omitempty"`
	Website               *string     `json:"website,omitempty"`
	ContactPersonName     *string     `json:"contact_person_name,omitempty"`
	ContactPersonRole     *string     `json:"contact_person_role,omitempty"`
	ContactPersonPhone    *string     `json:"contact_person_phone,omitempty"`
	ContactPersonEmail    *string     `json:"contact_person_email,omitempty"`
	PartnershipType       *string     `json:"partnership_type,omitempty"`
	PartnershipStartDate  *time.Time  `json:"partnership_start_date,omitempty"`
	PartnershipEndDate    *time.Time  `json:"partnership_end_date,omitempty"`
	PartnershipStatus     string      `json:"partnership_status"`
	OperatingRegions      []string    `json:"operating_regions,omitempty"`
	FocusAreas            []string    `json:"focus_areas,omitempty"`
	CanAccessReports      bool        `json:"can_access_reports"`
	ReportAccessLevel     *string     `json:"report_access_level,omitempty"`
	CustomReportFilters   interface{} `json:"custom_report_filters,omitempty"`
	LogoURL               *string     `json:"logo_url,omitempty"`
	BrandingColor         *string     `json:"branding_color,omitempty"`
}

func (r CreateNGOPartnerRequest) ToDomain() admin.NGOPartner {
	return admin.NGOPartner{
		UserID:                r.UserID,
		OrganizationName:      r.OrganizationName,
		OrganizationType:      r.OrganizationType,
		RegistrationNumber:    r.RegistrationNumber,
		TaxID:                 r.TaxID,
		OrganizationAddress:   r.OrganizationAddress,
		OrganizationPhone:     r.OrganizationPhone,
		OrganizationEmail:     r.OrganizationEmail,
		Website:               r.Website,
		ContactPersonName:     r.ContactPersonName,
		ContactPersonRole:     r.ContactPersonRole,
		ContactPersonPhone:    r.ContactPersonPhone,
		ContactPersonEmail:    r.ContactPersonEmail,
		PartnershipType:       r.PartnershipType,
		PartnershipStartDate:  r.PartnershipStartDate,
		PartnershipEndDate:    r.PartnershipEndDate,
		PartnershipStatus:     r.PartnershipStatus,
		OperatingRegions:      r.OperatingRegions,
		FocusAreas:            r.FocusAreas,
		CanAccessReports:      r.CanAccessReports,
		ReportAccessLevel:     r.ReportAccessLevel,
		CustomReportFilters:   r.CustomReportFilters,
		LogoURL:               r.LogoURL,
		BrandingColor:         r.BrandingColor,
	}
}

type NGOPartnerResponse struct {
	ID                   uuid.UUID   `json:"id"`
	UserID               uuid.UUID   `json:"user_id"`
	OrganizationName     string      `json:"organization_name"`
	OrganizationType     *string     `json:"organization_type,omitempty"`
	RegistrationNumber   *string     `json:"registration_number,omitempty"`
	TaxID                *string     `json:"tax_id,omitempty"`
	OrganizationAddress  *string     `json:"organization_address,omitempty"`
	OrganizationPhone    *string     `json:"organization_phone,omitempty"`
	OrganizationEmail    *string     `json:"organization_email,omitempty"`
	Website              *string     `json:"website,omitempty"`
	ContactPersonName    *string     `json:"contact_person_name,omitempty"`
	ContactPersonRole    *string     `json:"contact_person_role,omitempty"`
	ContactPersonPhone   *string     `json:"contact_person_phone,omitempty"`
	ContactPersonEmail   *string     `json:"contact_person_email,omitempty"`
	PartnershipType      *string     `json:"partnership_type,omitempty"`
	PartnershipStartDate *string     `json:"partnership_start_date,omitempty"`
	PartnershipEndDate   *string     `json:"partnership_end_date,omitempty"`
	PartnershipStatus    string      `json:"partnership_status"`
	OperatingRegions     []string    `json:"operating_regions,omitempty"`
	FocusAreas           []string    `json:"focus_areas,omitempty"`
	CanAccessReports     bool        `json:"can_access_reports"`
	ReportAccessLevel    *string     `json:"report_access_level,omitempty"`
	CustomReportFilters  interface{} `json:"custom_report_filters,omitempty"`
	LogoURL              *string     `json:"logo_url,omitempty"`
	BrandingColor        *string     `json:"branding_color,omitempty"`
	CreatedAt            string      `json:"created_at"`
	UpdatedAt            string      `json:"updated_at"`
}

func ToNGOPartnerResponse(partner admin.NGOPartner) NGOPartnerResponse {
	return NGOPartnerResponse{
		ID:                   partner.ID,
		UserID:               partner.UserID,
		OrganizationName:     partner.OrganizationName,
		OrganizationType:     partner.OrganizationType,
		RegistrationNumber:   partner.RegistrationNumber,
		TaxID:                partner.TaxID,
		OrganizationAddress:  partner.OrganizationAddress,
		OrganizationPhone:    partner.OrganizationPhone,
		OrganizationEmail:    partner.OrganizationEmail,
		Website:              partner.Website,
		ContactPersonName:    partner.ContactPersonName,
		ContactPersonRole:    partner.ContactPersonRole,
		ContactPersonPhone:   partner.ContactPersonPhone,
		ContactPersonEmail:   partner.ContactPersonEmail,
		PartnershipType:      partner.PartnershipType,
		PartnershipStartDate: timePtrToString(partner.PartnershipStartDate),
		PartnershipEndDate:   timePtrToString(partner.PartnershipEndDate),
		PartnershipStatus:    partner.PartnershipStatus,
		OperatingRegions:     partner.OperatingRegions,
		FocusAreas:           partner.FocusAreas,
		CanAccessReports:     partner.CanAccessReports,
		ReportAccessLevel:    partner.ReportAccessLevel,
		CustomReportFilters:  partner.CustomReportFilters,
		LogoURL:              partner.LogoURL,
		BrandingColor:        partner.BrandingColor,
		CreatedAt:            partner.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:            partner.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func timePtrToString(v *time.Time) *string {
	if v == nil {
		return nil
	}
	formatted := v.Format("2006-01-02T15:04:05Z07:00")
	return &formatted
}
