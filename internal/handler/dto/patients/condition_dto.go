package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateConditionRequest represents a request to create a condition record
type CreateConditionRequest struct {
	PatientID       uuid.UUID  `json:"patient_id"`
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"`
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"`
	Status          string     `json:"status"`
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
}

// UpdateConditionRequest represents a request to update a condition record
type UpdateConditionRequest struct {
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"`
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"`
	Status          string     `json:"status"`
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
}

// ConditionResponse represents a condition record in responses
type ConditionResponse struct {
	ID              uuid.UUID  `json:"id"`
	PatientID       uuid.UUID  `json:"patient_id"`
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"`
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"`
	Status          string     `json:"status"`
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ConditionsListResponse represents a list of conditions
type ConditionsListResponse struct {
	Conditions []ConditionResponse `json:"conditions"`
	Count      int                 `json:"count"`
}

// ToConditionResponse converts domain PatientCondition to response DTO
func ToConditionResponse(condition patients.PatientCondition) ConditionResponse {
	return ConditionResponse{
		ID:              condition.ID,
		PatientID:       condition.PatientID,
		ConditionName:   condition.ConditionName,
		ICD10Code:       condition.ICD10Code,
		Type:            condition.Type,
		DiagnosedDate:   condition.DiagnosedDate,
		DiagnosedBy:     condition.DiagnosedBy,
		Severity:        condition.Severity,
		Status:          condition.Status,
		Notes:           condition.Notes,
		LastFlareUp:     condition.LastFlareUp,
		NextCheckupDate: condition.NextCheckupDate,
		CreatedAt:       condition.CreatedAt,
		UpdatedAt:       condition.UpdatedAt,
	}
}

// ToDomainCondition converts request DTO to domain model
func ToDomainCondition(req CreateConditionRequest) patients.PatientCondition {
	return patients.PatientCondition{
		PatientID:       req.PatientID,
		ConditionName:   req.ConditionName,
		ICD10Code:       req.ICD10Code,
		Type:            req.Type,
		DiagnosedDate:   req.DiagnosedDate,
		DiagnosedBy:     req.DiagnosedBy,
		Severity:        req.Severity,
		Status:          req.Status,
		Notes:           req.Notes,
		LastFlareUp:     req.LastFlareUp,
		NextCheckupDate: req.NextCheckupDate,
	}
}

// UpdateToDomainCondition updates existing domain model with request data
func UpdateToDomainCondition(existing patients.PatientCondition, req UpdateConditionRequest) patients.PatientCondition {
	existing.ConditionName = req.ConditionName
	existing.ICD10Code = req.ICD10Code
	existing.Type = req.Type
	existing.DiagnosedDate = req.DiagnosedDate
	existing.DiagnosedBy = req.DiagnosedBy
	existing.Severity = req.Severity
	existing.Status = req.Status
	existing.Notes = req.Notes
	existing.LastFlareUp = req.LastFlareUp
	existing.NextCheckupDate = req.NextCheckupDate
	return existing
}
