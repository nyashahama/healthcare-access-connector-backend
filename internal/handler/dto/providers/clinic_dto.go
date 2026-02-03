package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// DTOs for Clinic

type CreateClinicRequest struct {
	ClinicName             string         `json:"clinic_name" binding:"required,min=1"`
	ClinicType             string         `json:"clinic_type" binding:"required,oneof=public_health_clinic private_clinic community_health_center mobile_clinic"`
	RegistrationNumber     *string        `json:"registration_number,omitempty"`
	AccreditationNumber    *string        `json:"accreditation_number,omitempty"`
	PrimaryPhone           *string        `json:"primary_phone,omitempty"`
	SecondaryPhone         *string        `json:"secondary_phone,omitempty"`
	EmergencyPhone         *string        `json:"emergency_phone,omitempty"`
	Email                  *string        `json:"email,omitempty"`
	Website                *string        `json:"website,omitempty"`
	PhysicalAddress        string         `json:"physical_address" binding:"required,min=1"`
	City                   *string        `json:"city,omitempty"`
	Province               *string        `json:"province,omitempty"`
	PostalCode             *string        `json:"postal_code,omitempty"`
	Country                string         `json:"country" binding:"required"`
	Latitude               *float64       `json:"latitude,omitempty"`
	Longitude              *float64       `json:"longitude,omitempty"`
	GooglePlaceID          *string        `json:"google_place_id,omitempty"`
	Description            *string        `json:"description,omitempty"`
	YearEstablished        *int           `json:"year_established,omitempty"`
	OwnershipType          *string        `json:"ownership_type,omitempty"`
	BedCount               *int           `json:"bed_count,omitempty" binding:"min=0"`
	OperatingHours         map[string]any `json:"operating_hours,omitempty"`
	Services               []string       `json:"services,omitempty"`
	Specialties            []string       `json:"specialties,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	Facilities             []string       `json:"facilities,omitempty"`
	AcceptsMedicalAid      bool           `json:"accepts_medical_aid"`
	MedicalAidProviders    []string       `json:"medical_aid_providers,omitempty"`
	PaymentMethods         []string       `json:"payment_methods,omitempty"`
	FeeStructure           *string        `json:"fee_structure,omitempty"`
	AccreditationBody      *string        `json:"accreditation_body,omitempty"`
	AccreditationExpiry    *time.Time     `json:"accreditation_expiry,omitempty"`
	Certifications         map[string]any `json:"certifications,omitempty"`
	PatientCapacity        *int           `json:"patient_capacity,omitempty"`
	AverageWaitTimeMinutes *int           `json:"average_wait_time_minutes,omitempty"`
	ContactPersonName      *string        `json:"contact_person_name,omitempty"`
	ContactPersonRole      *string        `json:"contact_person_role,omitempty"`
	ContactPersonPhone     *string        `json:"contact_person_phone,omitempty"`
	ContactPersonEmail     *string        `json:"contact_person_email,omitempty"`
}

type UpdateClinicRequest struct {
	ClinicName             string         `json:"clinic_name" binding:"required,min=1"`
	ClinicType             string         `json:"clinic_type" binding:"required,oneof=public_health_clinic private_clinic community_health_center mobile_clinic"`
	RegistrationNumber     *string        `json:"registration_number,omitempty"`
	AccreditationNumber    *string        `json:"accreditation_number,omitempty"`
	PrimaryPhone           *string        `json:"primary_phone,omitempty"`
	SecondaryPhone         *string        `json:"secondary_phone,omitempty"`
	EmergencyPhone         *string        `json:"emergency_phone,omitempty"`
	Email                  *string        `json:"email,omitempty"`
	Website                *string        `json:"website,omitempty"`
	PhysicalAddress        string         `json:"physical_address" binding:"required,min=1"`
	City                   *string        `json:"city,omitempty"`
	Province               *string        `json:"province,omitempty"`
	PostalCode             *string        `json:"postal_code,omitempty"`
	Country                string         `json:"country" binding:"required"`
	Latitude               *float64       `json:"latitude,omitempty"`
	Longitude              *float64       `json:"longitude,omitempty"`
	GooglePlaceID          *string        `json:"google_place_id,omitempty"`
	Description            *string        `json:"description,omitempty"`
	YearEstablished        *int           `json:"year_established,omitempty"`
	OwnershipType          *string        `json:"ownership_type,omitempty"`
	BedCount               *int           `json:"bed_count,omitempty" binding:"min=0"`
	OperatingHours         map[string]any `json:"operating_hours,omitempty"`
	Services               []string       `json:"services,omitempty"`
	Specialties            []string       `json:"specialties,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	Facilities             []string       `json:"facilities,omitempty"`
	AcceptsMedicalAid      bool           `json:"accepts_medical_aid"`
	MedicalAidProviders    []string       `json:"medical_aid_providers,omitempty"`
	PaymentMethods         []string       `json:"payment_methods,omitempty"`
	FeeStructure           *string        `json:"fee_structure,omitempty"`
	AccreditationBody      *string        `json:"accreditation_body,omitempty"`
	AccreditationExpiry    *time.Time     `json:"accreditation_expiry,omitempty"`
	Certifications         map[string]any `json:"certifications,omitempty"`
	PatientCapacity        *int           `json:"patient_capacity,omitempty"`
	AverageWaitTimeMinutes *int           `json:"average_wait_time_minutes,omitempty"`
	ContactPersonName      *string        `json:"contact_person_name,omitempty"`
	ContactPersonRole      *string        `json:"contact_person_role,omitempty"`
	ContactPersonPhone     *string        `json:"contact_person_phone,omitempty"`
	ContactPersonEmail     *string        `json:"contact_person_email,omitempty"`
}

type ClinicResponse struct {
	ID                     uuid.UUID      `json:"id"`
	ClinicName             string         `json:"clinic_name"`
	ClinicType             string         `json:"clinic_type"`
	RegistrationNumber     *string        `json:"registration_number,omitempty"`
	AccreditationNumber    *string        `json:"accreditation_number,omitempty"`
	PrimaryPhone           *string        `json:"primary_phone,omitempty"`
	SecondaryPhone         *string        `json:"secondary_phone,omitempty"`
	EmergencyPhone         *string        `json:"emergency_phone,omitempty"`
	Email                  *string        `json:"email,omitempty"`
	Website                *string        `json:"website,omitempty"`
	PhysicalAddress        string         `json:"physical_address"`
	City                   *string        `json:"city,omitempty"`
	Province               *string        `json:"province,omitempty"`
	PostalCode             *string        `json:"postal_code,omitempty"`
	Country                string         `json:"country"`
	Latitude               *float64       `json:"latitude,omitempty"`
	Longitude              *float64       `json:"longitude,omitempty"`
	GooglePlaceID          *string        `json:"google_place_id,omitempty"`
	Description            *string        `json:"description,omitempty"`
	YearEstablished        *int           `json:"year_established,omitempty"`
	OwnershipType          *string        `json:"ownership_type,omitempty"`
	BedCount               *int           `json:"bed_count,omitempty"`
	OperatingHours         map[string]any `json:"operating_hours,omitempty"`
	Services               []string       `json:"services,omitempty"`
	Specialties            []string       `json:"specialties,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	Facilities             []string       `json:"facilities,omitempty"`
	AcceptsMedicalAid      bool           `json:"accepts_medical_aid"`
	MedicalAidProviders    []string       `json:"medical_aid_providers,omitempty"`
	PaymentMethods         []string       `json:"payment_methods,omitempty"`
	FeeStructure           *string        `json:"fee_structure,omitempty"`
	AccreditationBody      *string        `json:"accreditation_body,omitempty"`
	AccreditationExpiry    *time.Time     `json:"accreditation_expiry,omitempty"`
	Certifications         map[string]any `json:"certifications,omitempty"`
	IsVerified             bool           `json:"is_verified"`
	VerificationStatus     string         `json:"verification_status"`
	VerificationNotes      *string        `json:"verification_notes,omitempty"`
	VerifiedBy             *uuid.UUID     `json:"verified_by,omitempty"`
	VerificationDate       *time.Time     `json:"verification_date,omitempty"`
	PatientCapacity        *int           `json:"patient_capacity,omitempty"`
	AverageWaitTimeMinutes *int           `json:"average_wait_time_minutes,omitempty"`
	Rating                 *float64       `json:"rating,omitempty"`
	ReviewCount            int            `json:"review_count"`
	ContactPersonName      *string        `json:"contact_person_name,omitempty"`
	ContactPersonRole      *string        `json:"contact_person_role,omitempty"`
	ContactPersonPhone     *string        `json:"contact_person_phone,omitempty"`
	ContactPersonEmail     *string        `json:"contact_person_email,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

type ClinicListResponse struct {
	Clinics []ClinicResponse `json:"clinics"`
	Total   int              `json:"total"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
}

type ClinicSearchResponse struct {
	Results []ClinicSearchResult `json:"results"`
	Total   int                  `json:"total"`
	Query   string               `json:"query"`
}

type VerifyClinicRequest struct {
	VerifiedBy uuid.UUID `json:"verified_by" binding:"required"`
	Notes      string    `json:"notes" binding:"required,min=1"`
}

type UpdateVerificationStatusRequest struct {
	Status string `json:"status" binding:"required,oneof=pending verified rejected in_review unverified"`
}

// Helper function to convert domain to response
func ClinicToResponse(clinic providers.Clinic) ClinicResponse {
	return ClinicResponse{
		ID:                     clinic.ID,
		ClinicName:             clinic.ClinicName,
		ClinicType:             clinic.ClinicType,
		RegistrationNumber:     clinic.RegistrationNumber,
		AccreditationNumber:    clinic.AccreditationNumber,
		PrimaryPhone:           clinic.PrimaryPhone,
		SecondaryPhone:         clinic.SecondaryPhone,
		EmergencyPhone:         clinic.EmergencyPhone,
		Email:                  clinic.Email,
		Website:                clinic.Website,
		PhysicalAddress:        clinic.PhysicalAddress,
		City:                   clinic.City,
		Province:               clinic.Province,
		PostalCode:             clinic.PostalCode,
		Country:                clinic.Country,
		Latitude:               clinic.Latitude,
		Longitude:              clinic.Longitude,
		GooglePlaceID:          clinic.GooglePlaceID,
		Description:            clinic.Description,
		YearEstablished:        clinic.YearEstablished,
		OwnershipType:          clinic.OwnershipType,
		BedCount:               clinic.BedCount,
		OperatingHours:         clinic.OperatingHours,
		Services:               clinic.Services,
		Specialties:            clinic.Specialties,
		LanguagesSpoken:        clinic.LanguagesSpoken,
		Facilities:             clinic.Facilities,
		AcceptsMedicalAid:      clinic.AcceptsMedicalAid,
		MedicalAidProviders:    clinic.MedicalAidProviders,
		PaymentMethods:         clinic.PaymentMethods,
		FeeStructure:           clinic.FeeStructure,
		AccreditationBody:      clinic.AccreditationBody,
		AccreditationExpiry:    clinic.AccreditationExpiry,
		Certifications:         clinic.Certifications,
		IsVerified:             clinic.IsVerified,
		VerificationStatus:     clinic.VerificationStatus,
		VerificationNotes:      clinic.VerificationNotes,
		VerifiedBy:             clinic.VerifiedBy,
		VerificationDate:       clinic.VerificationDate,
		PatientCapacity:        clinic.PatientCapacity,
		AverageWaitTimeMinutes: clinic.AverageWaitTimeMinutes,
		Rating:                 clinic.Rating,
		ReviewCount:            clinic.ReviewCount,
		ContactPersonName:      clinic.ContactPersonName,
		ContactPersonRole:      clinic.ContactPersonRole,
		ContactPersonPhone:     clinic.ContactPersonPhone,
		ContactPersonEmail:     clinic.ContactPersonEmail,
		CreatedAt:              clinic.CreatedAt,
		UpdatedAt:              clinic.UpdatedAt,
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
	Code   string            `json:"code,omitempty"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message"`
}

// ExistsResponse represents an existence check response
type ExistsResponse struct {
	Exists bool `json:"exists"`
}

// ClinicSearchResult represents a single search result
type ClinicSearchResult struct {
	ID              string   `json:"id"`
	ClinicName      string   `json:"clinic_name"`
	ClinicType      string   `json:"clinic_type"`
	City            *string  `json:"city,omitempty"`
	Province        *string  `json:"province,omitempty"`
	Distance        *float64 `json:"distance,omitempty"`
	Rating          *float64 `json:"rating,omitempty"`
	IsVerified      bool     `json:"is_verified"`
	PhysicalAddress string   `json:"physical_address"`
}

// Helper functions for string pointer conversions
func stringPtr(s string) *string {
	return &s
}

func stringPtrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
