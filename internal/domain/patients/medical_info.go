package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientMedicalInfo represents core medical information and vitals
type PatientMedicalInfo struct {
	ID                     uuid.UUID  `json:"id"`
	PatientID              uuid.UUID  `json:"patient_id"`
	BloodType              *string    `json:"blood_type,omitempty"` // 'A+', 'O-', etc.
	BloodTypeLastTested    *time.Time `json:"blood_type_last_tested,omitempty"`
	HeightCm               *float64   `json:"height_cm,omitempty"`
	WeightKg               *float64   `json:"weight_kg,omitempty"`
	BMI                    *float64   `json:"bmi,omitempty"`
	LastMeasuredDate       *time.Time `json:"last_measured_date,omitempty"`
	OverallHealthStatus    *string    `json:"overall_health_status,omitempty"` // 'excellent', 'good', 'fair', 'poor'
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

// VitalStats represents basic vital statistics
type VitalStats struct {
	HeightCm         *float64   `json:"height_cm,omitempty"`
	WeightKg         *float64   `json:"weight_kg,omitempty"`
	BMI              *float64   `json:"bmi,omitempty"`
	LastMeasuredDate *time.Time `json:"last_measured_date,omitempty"`
}

// MedicalInfoSummary provides aggregated medical information statistics
type MedicalInfoSummary struct {
	TotalRecords         int64   `json:"total_records"`
	WithBloodType        int64   `json:"with_blood_type"`
	OrganDonors          int64   `json:"organ_donors"`
	WithAdvanceDirective int64   `json:"with_advance_directive"`
	WithDNR              int64   `json:"with_dnr"`
	AverageHeight        float64 `json:"average_height_cm"`
	AverageWeight        float64 `json:"average_weight_kg"`
	AverageBMI           float64 `json:"average_bmi"`
	ExcellentHealthCount int64   `json:"excellent_health_count"`
	GoodHealthCount      int64   `json:"good_health_count"`
	FairHealthCount      int64   `json:"fair_health_count"`
	PoorHealthCount      int64   `json:"poor_health_count"`
}
