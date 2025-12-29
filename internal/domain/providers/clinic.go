package providers

import (
	"time"

	"github.com/google/uuid"
)

// Clinic represents a healthcare facility
type Clinic struct {
	ID                     uuid.UUID      `json:"id"`
	ClinicName             string         `json:"clinic_name"`
	ClinicType             string         `json:"clinic_type"` // public_health_clinic, private_clinic, community_health_center, mobile_clinic
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
	OwnershipType          *string        `json:"ownership_type,omitempty"` // government, private, ngo, religious
	BedCount               *int           `json:"bed_count,omitempty"`
	OperatingHours         map[string]any `json:"operating_hours,omitempty"`
	Services               []string       `json:"services,omitempty"`
	Specialties            []string       `json:"specialties,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	Facilities             []string       `json:"facilities,omitempty"`
	AcceptsMedicalAid      bool           `json:"accepts_medical_aid"`
	MedicalAidProviders    []string       `json:"medical_aid_providers,omitempty"`
	PaymentMethods         []string       `json:"payment_methods,omitempty"`
	FeeStructure           *string        `json:"fee_structure,omitempty"` // free, sliding_scale, fixed_fees
	AccreditationBody      *string        `json:"accreditation_body,omitempty"`
	AccreditationExpiry    *time.Time     `json:"accreditation_expiry,omitempty"`
	IsVerified             bool           `json:"is_verified"`
	VerificationStatus     string         `json:"verification_status"` // pending, verified, rejected
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

// ClinicFilters represents filters for clinic search
type ClinicFilters struct {
	ClinicType         *string
	Province           *string
	City               *string
	VerificationStatus *string
	AcceptsMedicalAid  *bool
}