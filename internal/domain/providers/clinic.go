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

// ============================================
// SUPPORTING TYPES - CLINIC REPOSITORY
// ============================================

type ClinicLocation struct {
	PhysicalAddress string
	City            *string
	Province        *string
	PostalCode      *string
	Country         *string
	Latitude        *float64
	Longitude       *float64
	GooglePlaceID   *string
}

type ClinicContact struct {
	PrimaryPhone       *string
	SecondaryPhone     *string
	EmergencyPhone     *string
	Email              *string
	Website            *string
	ContactPersonName  *string
	ContactPersonRole  *string
	ContactPersonPhone *string
	ContactPersonEmail *string
}

type ClinicServicesUpdate struct {
	Services        []string
	Specialties     []string
	Facilities      []string
	LanguagesSpoken []string
}

type ClinicPaymentInfo struct {
	AcceptsMedicalAid   bool
	MedicalAidProviders []string
	PaymentMethods      []string
	FeeStructure        *string
}

type ClinicAccreditation struct {
	AccreditationNumber *string
	AccreditationBody   *string
	AccreditationExpiry *time.Time
	Certifications      map[string]any
}

type ClinicSearchParams struct {
	Query      string
	Province   *string
	City       *string
	ClinicType *string
	Limit      int
	Offset     int
}

type ClinicSearchResult struct {
	Clinic     Clinic   `json:"clinic"`
	DistanceKm *float64 `json:"distance_km,omitempty"`
}

type ClinicStatistics struct {
	ID                  uuid.UUID
	ClinicName          string
	ReviewCount         int
	Rating              *float64
	PatientCapacity     *int
	BedCount            *int
	AverageWaitTime     *int
	ActiveStaffCount    int64
	TotalStaffCount     int64
	ActiveServicesCount int64
	TotalServicesCount  int64
}

type ClinicMetrics struct {
	TotalClinics    int64
	VerifiedClinics int64
	PendingClinics  int64
	RejectedClinics int64
	ActiveClinics   int64
	AverageRating   *float64
	TotalReviews    int64
	AverageCapacity *float64
	TotalBeds       int64
}

type ClinicTypeDistribution struct {
	ClinicType    string
	Count         int64
	AverageRating *float64
}

type ClinicProvinceDistribution struct {
	Province      string
	Count         int64
	AverageRating *float64
}

type ClinicOwnershipDistribution struct {
	OwnershipType string
	Count         int64
	AverageRating *float64
}

type ClinicAdvancedSearchParams struct {
	Query             *string
	Province          *string
	City              *string
	ClinicType        *string
	OwnershipType     *string
	AcceptsMedicalAid *bool
	Services          map[string]any
	Specialties       map[string]any
	Limit             int
	Offset            int
}

type ClinicAccreditationInfo struct {
	ID                  uuid.UUID
	ClinicName          string
	AccreditationNumber *string
	AccreditationBody   *string
	AccreditationExpiry *time.Time
	Email               *string
	PrimaryPhone        *string
}
