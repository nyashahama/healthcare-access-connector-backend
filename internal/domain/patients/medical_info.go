package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientMedicalInfo represents patient medical information
type PatientMedicalInfo struct {
	ID                     uuid.UUID  `json:"id"`
	PatientID              uuid.UUID  `json:"patient_id"`
	BloodType              *string    `json:"blood_type,omitempty"`
	BloodTypeLastTested    *time.Time `json:"blood_type_last_tested,omitempty"`
	HeightCm               *float64   `json:"height_cm,omitempty"`
	WeightKg               *float64   `json:"weight_kg,omitempty"`
	BMI                    *float64   `json:"bmi,omitempty"`
	LastMeasuredDate       *time.Time `json:"last_measured_date,omitempty"`
	OverallHealthStatus    *string    `json:"overall_health_status,omitempty"`
	HealthSummary          *string    `json:"health_summary,omitempty"`
	PrimaryCarePhysician   *string    `json:"primary_care_physician,omitempty"`
	PrimaryClinicID        *uuid.UUID `json:"primary_clinic_id,omitempty"`
	OrganDonor             bool       `json:"organ_donor"`
	AdvanceDirectiveExists bool       `json:"advance_directive_exists"`
	AdvanceDirectiveURL    *string    `json:"advance_directive_url,omitempty"`
	DNRStatus              bool       `json:"dnr_status"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}