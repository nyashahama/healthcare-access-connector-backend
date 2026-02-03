package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateMedicalInfoRequest represents a request to create medical info
type CreateMedicalInfoRequest struct {
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
}

// UpdateMedicalInfoRequest represents a request to update medical info
type UpdateMedicalInfoRequest struct {
	BloodType            *string    `json:"blood_type,omitempty"`
	BloodTypeLastTested  *time.Time `json:"blood_type_last_tested,omitempty"`
	HeightCm             *float64   `json:"height_cm,omitempty"`
	WeightKg             *float64   `json:"weight_kg,omitempty"`
	BMI                  *float64   `json:"bmi,omitempty"`
	LastMeasuredDate     *time.Time `json:"last_measured_date,omitempty"`
	OverallHealthStatus  *string    `json:"overall_health_status,omitempty"`
	HealthSummary        *string    `json:"health_summary,omitempty"`
	PrimaryCarePhysician *string    `json:"primary_care_physician,omitempty"`
	PrimaryClinicID      *uuid.UUID `json:"primary_clinic_id,omitempty"`
}

// MedicalInfoResponse represents medical info in responses
type MedicalInfoResponse struct {
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

// ToMedicalInfoResponse converts domain PatientMedicalInfo to response DTO
func ToMedicalInfoResponse(info patients.PatientMedicalInfo) MedicalInfoResponse {
	return MedicalInfoResponse{
		ID:                     info.ID,
		PatientID:              info.PatientID,
		BloodType:              info.BloodType,
		BloodTypeLastTested:    info.BloodTypeLastTested,
		HeightCm:               info.HeightCm,
		WeightKg:               info.WeightKg,
		BMI:                    info.BMI,
		LastMeasuredDate:       info.LastMeasuredDate,
		OverallHealthStatus:    info.OverallHealthStatus,
		HealthSummary:          info.HealthSummary,
		PrimaryCarePhysician:   info.PrimaryCarePhysician,
		PrimaryClinicID:        info.PrimaryClinicID,
		OrganDonor:             info.OrganDonor,
		AdvanceDirectiveExists: info.AdvanceDirectiveExists,
		AdvanceDirectiveURL:    info.AdvanceDirectiveURL,
		DNRStatus:              info.DNRStatus,
		CreatedAt:              info.CreatedAt,
		UpdatedAt:              info.UpdatedAt,
	}
}

// ToDomainMedicalInfo converts request DTO to domain model
func ToDomainMedicalInfo(req CreateMedicalInfoRequest) patients.PatientMedicalInfo {
	return patients.PatientMedicalInfo{
		PatientID:              req.PatientID,
		BloodType:              req.BloodType,
		BloodTypeLastTested:    req.BloodTypeLastTested,
		HeightCm:               req.HeightCm,
		WeightKg:               req.WeightKg,
		BMI:                    req.BMI,
		LastMeasuredDate:       req.LastMeasuredDate,
		OverallHealthStatus:    req.OverallHealthStatus,
		HealthSummary:          req.HealthSummary,
		PrimaryCarePhysician:   req.PrimaryCarePhysician,
		PrimaryClinicID:        req.PrimaryClinicID,
		OrganDonor:             req.OrganDonor,
		AdvanceDirectiveExists: req.AdvanceDirectiveExists,
		AdvanceDirectiveURL:    req.AdvanceDirectiveURL,
		DNRStatus:              req.DNRStatus,
	}
}

// UpdateToDomainMedicalInfo updates existing domain model with request data
func UpdateToDomainMedicalInfo(existing patients.PatientMedicalInfo, req UpdateMedicalInfoRequest) patients.PatientMedicalInfo {
	existing.BloodType = req.BloodType
	existing.BloodTypeLastTested = req.BloodTypeLastTested
	existing.HeightCm = req.HeightCm
	existing.WeightKg = req.WeightKg
	existing.BMI = req.BMI
	existing.LastMeasuredDate = req.LastMeasuredDate
	existing.OverallHealthStatus = req.OverallHealthStatus
	existing.HealthSummary = req.HealthSummary
	existing.PrimaryCarePhysician = req.PrimaryCarePhysician
	existing.PrimaryClinicID = req.PrimaryClinicID
	return existing
}
