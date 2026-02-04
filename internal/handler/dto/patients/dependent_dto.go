package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateDependentRequest represents a request to create a dependent record
type CreateDependentRequest struct {
	PatientID               uuid.UUID  `json:"patient_id"`
	FirstName               string     `json:"first_name"`
	LastName                string     `json:"last_name"`
	DateOfBirth             time.Time  `json:"date_of_birth"`
	Gender                  *string    `json:"gender,omitempty"`
	Relationship            string     `json:"relationship"` // 'child', 'ward', 'dependent_adult'
	BloodType               *string    `json:"blood_type,omitempty"`
	HealthStatus            *string    `json:"health_status,omitempty"` // 'excellent', 'good', 'fair', 'poor'
	PrimaryPediatrician     *string    `json:"primary_pediatrician,omitempty"`
	ClinicID                *uuid.UUID `json:"clinic_id,omitempty"`
	BirthWeightKg           *float64   `json:"birth_weight_kg,omitempty"`
	BirthHeightCm           *float64   `json:"birth_height_cm,omitempty"`
	SchoolName              *string    `json:"school_name,omitempty"`
	Grade                   *string    `json:"grade,omitempty"`
	HasLegalGuardianship    bool       `json:"has_legal_guardianship"`
	GuardianshipDocumentURL *string    `json:"guardianship_document_url,omitempty"`
	HasSpecialNeeds         bool       `json:"has_special_needs"`
	SpecialNeedsDescription *string    `json:"special_needs_description,omitempty"`
}

// UpdateDependentRequest represents a request to update a dependent record
type UpdateDependentRequest struct {
	FirstName               string     `json:"first_name"`
	LastName                string     `json:"last_name"`
	DateOfBirth             time.Time  `json:"date_of_birth"`
	Gender                  *string    `json:"gender,omitempty"`
	Relationship            string     `json:"relationship"` // 'child', 'ward', 'dependent_adult'
	BloodType               *string    `json:"blood_type,omitempty"`
	HealthStatus            *string    `json:"health_status,omitempty"` // 'excellent', 'good', 'fair', 'poor'
	PrimaryPediatrician     *string    `json:"primary_pediatrician,omitempty"`
	ClinicID                *uuid.UUID `json:"clinic_id,omitempty"`
	BirthWeightKg           *float64   `json:"birth_weight_kg,omitempty"`
	BirthHeightCm           *float64   `json:"birth_height_cm,omitempty"`
	SchoolName              *string    `json:"school_name,omitempty"`
	Grade                   *string    `json:"grade,omitempty"`
	HasLegalGuardianship    bool       `json:"has_legal_guardianship"`
	GuardianshipDocumentURL *string    `json:"guardianship_document_url,omitempty"`
	HasSpecialNeeds         bool       `json:"has_special_needs"`
	SpecialNeedsDescription *string    `json:"special_needs_description,omitempty"`
}

// DependentResponse represents a dependent record in responses
type DependentResponse struct {
	ID                      uuid.UUID  `json:"id"`
	PatientID               uuid.UUID  `json:"patient_id"`
	FirstName               string     `json:"first_name"`
	LastName                string     `json:"last_name"`
	DateOfBirth             time.Time  `json:"date_of_birth"`
	Gender                  *string    `json:"gender,omitempty"`
	Relationship            string     `json:"relationship"` // 'child', 'ward', 'dependent_adult'
	BloodType               *string    `json:"blood_type,omitempty"`
	HealthStatus            *string    `json:"health_status,omitempty"` // 'excellent', 'good', 'fair', 'poor'
	PrimaryPediatrician     *string    `json:"primary_pediatrician,omitempty"`
	ClinicID                *uuid.UUID `json:"clinic_id,omitempty"`
	BirthWeightKg           *float64   `json:"birth_weight_kg,omitempty"`
	BirthHeightCm           *float64   `json:"birth_height_cm,omitempty"`
	SchoolName              *string    `json:"school_name,omitempty"`
	Grade                   *string    `json:"grade,omitempty"`
	HasLegalGuardianship    bool       `json:"has_legal_guardianship"`
	GuardianshipDocumentURL *string    `json:"guardianship_document_url,omitempty"`
	HasSpecialNeeds         bool       `json:"has_special_needs"`
	SpecialNeedsDescription *string    `json:"special_needs_description,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

// DependentsListResponse represents a list of dependents
type DependentsListResponse struct {
	Dependents []DependentResponse `json:"dependents"`
	Count      int                 `json:"count"`
}

// ToDependentResponse converts domain PatientDependent to response DTO
func ToDependentResponse(dependent patients.PatientDependent) DependentResponse {
	return DependentResponse{
		ID:                      dependent.ID,
		PatientID:               dependent.PatientID,
		FirstName:               dependent.FirstName,
		LastName:                dependent.LastName,
		DateOfBirth:             dependent.DateOfBirth,
		Gender:                  dependent.Gender,
		Relationship:            dependent.Relationship,
		BloodType:               dependent.BloodType,
		HealthStatus:            dependent.HealthStatus,
		PrimaryPediatrician:     dependent.PrimaryPediatrician,
		ClinicID:                dependent.ClinicID,
		BirthWeightKg:           dependent.BirthWeightKg,
		BirthHeightCm:           dependent.BirthHeightCm,
		SchoolName:              dependent.SchoolName,
		Grade:                   dependent.Grade,
		HasLegalGuardianship:    dependent.HasLegalGuardianship,
		GuardianshipDocumentURL: dependent.GuardianshipDocumentURL,
		HasSpecialNeeds:         dependent.HasSpecialNeeds,
		SpecialNeedsDescription: dependent.SpecialNeedsDescription,
		CreatedAt:               dependent.CreatedAt,
		UpdatedAt:               dependent.UpdatedAt,
	}
}

// ToDomainDependent converts request DTO to domain model
func ToDomainDependent(req CreateDependentRequest) patients.PatientDependent {
	return patients.PatientDependent{
		PatientID:               req.PatientID,
		FirstName:               req.FirstName,
		LastName:                req.LastName,
		DateOfBirth:             req.DateOfBirth,
		Gender:                  req.Gender,
		Relationship:            req.Relationship,
		BloodType:               req.BloodType,
		HealthStatus:            req.HealthStatus,
		PrimaryPediatrician:     req.PrimaryPediatrician,
		ClinicID:                req.ClinicID,
		BirthWeightKg:           req.BirthWeightKg,
		BirthHeightCm:           req.BirthHeightCm,
		SchoolName:              req.SchoolName,
		Grade:                   req.Grade,
		HasLegalGuardianship:    req.HasLegalGuardianship,
		GuardianshipDocumentURL: req.GuardianshipDocumentURL,
		HasSpecialNeeds:         req.HasSpecialNeeds,
		SpecialNeedsDescription: req.SpecialNeedsDescription,
	}
}

// UpdateToDomainDependent updates existing domain model with request data
func UpdateToDomainDependent(existing patients.PatientDependent, req UpdateDependentRequest) patients.PatientDependent {
	existing.FirstName = req.FirstName
	existing.LastName = req.LastName
	existing.DateOfBirth = req.DateOfBirth
	existing.Gender = req.Gender
	existing.Relationship = req.Relationship
	existing.BloodType = req.BloodType
	existing.HealthStatus = req.HealthStatus
	existing.PrimaryPediatrician = req.PrimaryPediatrician
	existing.ClinicID = req.ClinicID
	existing.BirthWeightKg = req.BirthWeightKg
	existing.BirthHeightCm = req.BirthHeightCm
	existing.SchoolName = req.SchoolName
	existing.Grade = req.Grade
	existing.HasLegalGuardianship = req.HasLegalGuardianship
	existing.GuardianshipDocumentURL = req.GuardianshipDocumentURL
	existing.HasSpecialNeeds = req.HasSpecialNeeds
	existing.SpecialNeedsDescription = req.SpecialNeedsDescription
	return existing
}
