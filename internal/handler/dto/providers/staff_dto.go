package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// DTOs for Staff

type CreateStaffRequest struct {
	ClinicID               uuid.UUID      `json:"clinic_id" binding:"required"`
	UserID                 uuid.UUID      `json:"user_id" binding:"required"`
	Title                  *string        `json:"title,omitempty"`
	FirstName              string         `json:"first_name" binding:"required,min=1"`
	LastName               string         `json:"last_name" binding:"required,min=1"`
	ProfessionalTitle      *string        `json:"professional_title,omitempty"`
	Specialization         *string        `json:"specialization,omitempty"`
	WorkEmail              *string        `json:"work_email,omitempty"`
	WorkPhone              *string        `json:"work_phone,omitempty"`
	PersonalPhone          *string        `json:"personal_phone,omitempty"`
	HPCSNumber             *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers    map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications         []string       `json:"qualifications,omitempty"`
	YearsExperience        *int           `json:"years_experience,omitempty"`
	Bio                    *string        `json:"bio,omitempty"`
	StaffRole              string         `json:"staff_role" binding:"required,oneof=doctor nurse administrator receptionist manager"`
	Department             *string        `json:"department,omitempty"`
	IsPrimaryContact       bool           `json:"is_primary_contact"`
	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status" binding:"oneof=active on_leave terminated"`
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
}

type UpdateStaffRequest struct {
	Title                  *string        `json:"title,omitempty"`
	FirstName              string         `json:"first_name" binding:"required,min=1"`
	LastName               string         `json:"last_name" binding:"required,min=1"`
	ProfessionalTitle      *string        `json:"professional_title,omitempty"`
	Specialization         *string        `json:"specialization,omitempty"`
	WorkEmail              *string        `json:"work_email,omitempty"`
	WorkPhone              *string        `json:"work_phone,omitempty"`
	PersonalPhone          *string        `json:"personal_phone,omitempty"`
	HPCSNumber             *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers    map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications         []string       `json:"qualifications,omitempty"`
	YearsExperience        *int           `json:"years_experience,omitempty"`
	Bio                    *string        `json:"bio,omitempty"`
	StaffRole              string         `json:"staff_role" binding:"oneof=doctor nurse administrator receptionist manager"`
	Department             *string        `json:"department,omitempty"`
	IsPrimaryContact       bool           `json:"is_primary_contact"`
	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status" binding:"oneof=active on_leave terminated"`
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
}

type StaffResponse struct {
	ID                     uuid.UUID      `json:"id"`
	ClinicID               uuid.UUID      `json:"clinic_id"`
	UserID                 uuid.UUID      `json:"user_id"`
	Title                  *string        `json:"title,omitempty"`
	FirstName              string         `json:"first_name"`
	LastName               string         `json:"last_name"`
	ProfessionalTitle      *string        `json:"professional_title,omitempty"`
	Specialization         *string        `json:"specialization,omitempty"`
	WorkEmail              *string        `json:"work_email,omitempty"`
	WorkPhone              *string        `json:"work_phone,omitempty"`
	PersonalPhone          *string        `json:"personal_phone,omitempty"`
	HPCSNumber             *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers    map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications         []string       `json:"qualifications,omitempty"`
	YearsExperience        *int           `json:"years_experience,omitempty"`
	Bio                    *string        `json:"bio,omitempty"`
	StaffRole              string         `json:"staff_role"`
	Department             *string        `json:"department,omitempty"`
	IsPrimaryContact       bool           `json:"is_primary_contact"`
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

type StaffListResponse struct {
	Staff []StaffResponse `json:"staff"`
	Total int             `json:"total"`
}

// Helper function to convert domain to response
func StaffToResponse(staff providers.ClinicStaff) StaffResponse {
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
