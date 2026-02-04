package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// CreateClinicRequest represents a request to create a clinic
type CreateClinicRequest struct {
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
	PatientCapacity        *int           `json:"patient_capacity,omitempty"`
	AverageWaitTimeMinutes *int           `json:"average_wait_time_minutes,omitempty"`
	ContactPersonName      *string        `json:"contact_person_name,omitempty"`
	ContactPersonRole      *string        `json:"contact_person_role,omitempty"`
	ContactPersonPhone     *string        `json:"contact_person_phone,omitempty"`
	ContactPersonEmail     *string        `json:"contact_person_email,omitempty"`
}

// UpdateClinicRequest represents a request to update a clinic
type UpdateClinicRequest struct {
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
	PatientCapacity        *int           `json:"patient_capacity,omitempty"`
	AverageWaitTimeMinutes *int           `json:"average_wait_time_minutes,omitempty"`
	ContactPersonName      *string        `json:"contact_person_name,omitempty"`
	ContactPersonRole      *string        `json:"contact_person_role,omitempty"`
	ContactPersonPhone     *string        `json:"contact_person_phone,omitempty"`
	ContactPersonEmail     *string        `json:"contact_person_email,omitempty"`
}

// ClinicResponse represents a clinic in responses
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

// VerifyClinicRequest represents a request to verify a clinic
type VerifyClinicRequest struct {
	VerifiedBy uuid.UUID `json:"verified_by"`
	Notes      string    `json:"notes"`
}

// UpdateVerificationStatusRequest represents a request to update verification status
type UpdateVerificationStatusRequest struct {
	Status string `json:"status"`
}

// ClinicListResponse represents a list of clinics
type ClinicListResponse struct {
	Clinics []ClinicResponse `json:"clinics"`
	Total   int              `json:"total"`
	Limit   int              `json:"limit,omitempty"`
	Offset  int              `json:"offset,omitempty"`
}

// ToClinicResponse converts domain Clinic to response DTO
func ToClinicResponse(clinic providers.Clinic) ClinicResponse {
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

// ToDomainClinic converts request DTO to domain model
func ToDomainClinic(req CreateClinicRequest) providers.Clinic {
	return providers.Clinic{
		ClinicName:             req.ClinicName,
		ClinicType:             req.ClinicType,
		RegistrationNumber:     req.RegistrationNumber,
		AccreditationNumber:    req.AccreditationNumber,
		PrimaryPhone:           req.PrimaryPhone,
		SecondaryPhone:         req.SecondaryPhone,
		EmergencyPhone:         req.EmergencyPhone,
		Email:                  req.Email,
		Website:                req.Website,
		PhysicalAddress:        req.PhysicalAddress,
		City:                   req.City,
		Province:               req.Province,
		PostalCode:             req.PostalCode,
		Country:                req.Country,
		Latitude:               req.Latitude,
		Longitude:              req.Longitude,
		GooglePlaceID:          req.GooglePlaceID,
		Description:            req.Description,
		YearEstablished:        req.YearEstablished,
		OwnershipType:          req.OwnershipType,
		BedCount:               req.BedCount,
		OperatingHours:         req.OperatingHours,
		Services:               req.Services,
		Specialties:            req.Specialties,
		LanguagesSpoken:        req.LanguagesSpoken,
		Facilities:             req.Facilities,
		AcceptsMedicalAid:      req.AcceptsMedicalAid,
		MedicalAidProviders:    req.MedicalAidProviders,
		PaymentMethods:         req.PaymentMethods,
		FeeStructure:           req.FeeStructure,
		AccreditationBody:      req.AccreditationBody,
		AccreditationExpiry:    req.AccreditationExpiry,
		Certifications:         req.Certifications,
		PatientCapacity:        req.PatientCapacity,
		AverageWaitTimeMinutes: req.AverageWaitTimeMinutes,
		ContactPersonName:      req.ContactPersonName,
		ContactPersonRole:      req.ContactPersonRole,
		ContactPersonPhone:     req.ContactPersonPhone,
		ContactPersonEmail:     req.ContactPersonEmail,
	}
}

// UpdateToDomainClinic updates existing domain model with request data
func UpdateToDomainClinic(existing providers.Clinic, req UpdateClinicRequest) providers.Clinic {
	existing.ClinicName = req.ClinicName
	existing.ClinicType = req.ClinicType
	existing.RegistrationNumber = req.RegistrationNumber
	existing.AccreditationNumber = req.AccreditationNumber
	existing.PrimaryPhone = req.PrimaryPhone
	existing.SecondaryPhone = req.SecondaryPhone
	existing.EmergencyPhone = req.EmergencyPhone
	existing.Email = req.Email
	existing.Website = req.Website
	existing.PhysicalAddress = req.PhysicalAddress
	existing.City = req.City
	existing.Province = req.Province
	existing.PostalCode = req.PostalCode
	existing.Country = req.Country
	existing.Latitude = req.Latitude
	existing.Longitude = req.Longitude
	existing.GooglePlaceID = req.GooglePlaceID
	existing.Description = req.Description
	existing.YearEstablished = req.YearEstablished
	existing.OwnershipType = req.OwnershipType
	existing.BedCount = req.BedCount
	existing.OperatingHours = req.OperatingHours
	if len(req.Services) > 0 {
		existing.Services = req.Services
	}
	if len(req.Specialties) > 0 {
		existing.Specialties = req.Specialties
	}
	if len(req.LanguagesSpoken) > 0 {
		existing.LanguagesSpoken = req.LanguagesSpoken
	}
	if len(req.Facilities) > 0 {
		existing.Facilities = req.Facilities
	}
	existing.AcceptsMedicalAid = req.AcceptsMedicalAid
	if len(req.MedicalAidProviders) > 0 {
		existing.MedicalAidProviders = req.MedicalAidProviders
	}
	if len(req.PaymentMethods) > 0 {
		existing.PaymentMethods = req.PaymentMethods
	}
	existing.FeeStructure = req.FeeStructure
	existing.AccreditationBody = req.AccreditationBody
	existing.AccreditationExpiry = req.AccreditationExpiry
	existing.Certifications = req.Certifications
	existing.PatientCapacity = req.PatientCapacity
	existing.AverageWaitTimeMinutes = req.AverageWaitTimeMinutes
	existing.ContactPersonName = req.ContactPersonName
	existing.ContactPersonRole = req.ContactPersonRole
	existing.ContactPersonPhone = req.ContactPersonPhone
	existing.ContactPersonEmail = req.ContactPersonEmail
	return existing
}
