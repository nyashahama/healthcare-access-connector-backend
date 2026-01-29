package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientDependent represents a dependent (child/ward) of a patient
type PatientDependent struct {
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

// DependentStatistics provides statistics for a patient's dependents
type DependentStatistics struct {
	TotalDependents     int64   `json:"total_dependents"`
	ChildrenCount       int64   `json:"children_count"`
	SpecialNeedsCount   int64   `json:"special_needs_count"`
	WithoutGuardianship int64   `json:"without_guardianship"`
	AverageAge          float64 `json:"average_age"`
}

// DependentSystemMetrics provides system-wide dependent metrics
type DependentSystemMetrics struct {
	PatientsWithDependents int64   `json:"patients_with_dependents"`
	TotalDependents        int64   `json:"total_dependents"`
	Children               int64   `json:"children"`
	WithSpecialNeeds       int64   `json:"with_special_needs"`
	AvgAge                 float64 `json:"avg_age"`
	Under5                 int64   `json:"under_5"`
	Age5To12               int64   `json:"age_5_to_12"`
	Age13To18              int64   `json:"age_13_to_18"`
}

// AgeGroupDistribution represents age distribution of dependents
type AgeGroupDistribution struct {
	AgeGroup       string `json:"age_group"`
	DependentCount int64  `json:"dependent_count"`
}
