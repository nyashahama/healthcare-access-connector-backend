package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateFamilyHistoryRequest represents a request to create a family history record
type CreateFamilyHistoryRequest struct {
	PatientID              uuid.UUID `json:"patient_id"`
	Relative               string    `json:"relative"`
	RelativeAgeAtDiagnosis *int      `json:"relative_age_at_diagnosis,omitempty"`
	ConditionName          string    `json:"condition_name"`
	Notes                  *string   `json:"notes,omitempty"`
	IsAlive                *bool     `json:"is_alive,omitempty"`
	CauseOfDeath           *string   `json:"cause_of_death,omitempty"`
	AgeAtDeath             *int      `json:"age_at_death,omitempty"`
}

// UpdateFamilyHistoryRequest represents a request to update a family history record
type UpdateFamilyHistoryRequest struct {
	Relative               string  `json:"relative"`
	RelativeAgeAtDiagnosis *int    `json:"relative_age_at_diagnosis,omitempty"`
	ConditionName          string  `json:"condition_name"`
	Notes                  *string `json:"notes,omitempty"`
	IsAlive                *bool   `json:"is_alive,omitempty"`
	CauseOfDeath           *string `json:"cause_of_death,omitempty"`
	AgeAtDeath             *int    `json:"age_at_death,omitempty"`
}

// FamilyHistoryResponse represents a family history record in responses
type FamilyHistoryResponse struct {
	ID                     uuid.UUID `json:"id"`
	PatientID              uuid.UUID `json:"patient_id"`
	Relative               string    `json:"relative"`
	RelativeAgeAtDiagnosis *int      `json:"relative_age_at_diagnosis,omitempty"`
	ConditionName          string    `json:"condition_name"`
	Notes                  *string   `json:"notes,omitempty"`
	IsAlive                *bool     `json:"is_alive,omitempty"`
	CauseOfDeath           *string   `json:"cause_of_death,omitempty"`
	AgeAtDeath             *int      `json:"age_at_death,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
}

// FamilyHistoriesListResponse represents a list of family histories
type FamilyHistoriesListResponse struct {
	FamilyHistories []FamilyHistoryResponse `json:"family_histories"`
	Count           int                     `json:"count"`
}

// ToFamilyHistoryResponse converts domain PatientFamilyHistory to response DTO
func ToFamilyHistoryResponse(history patients.PatientFamilyHistory) FamilyHistoryResponse {
	return FamilyHistoryResponse{
		ID:                     history.ID,
		PatientID:              history.PatientID,
		Relative:               history.Relative,
		RelativeAgeAtDiagnosis: history.RelativeAgeAtDiagnosis,
		ConditionName:          history.ConditionName,
		Notes:                  history.Notes,
		IsAlive:                history.IsAlive,
		CauseOfDeath:           history.CauseOfDeath,
		AgeAtDeath:             history.AgeAtDeath,
		CreatedAt:              history.CreatedAt,
	}
}

// ToDomainFamilyHistory converts request DTO to domain model
func ToDomainFamilyHistory(req CreateFamilyHistoryRequest) patients.PatientFamilyHistory {
	return patients.PatientFamilyHistory{
		PatientID:              req.PatientID,
		Relative:               req.Relative,
		RelativeAgeAtDiagnosis: req.RelativeAgeAtDiagnosis,
		ConditionName:          req.ConditionName,
		Notes:                  req.Notes,
		IsAlive:                req.IsAlive,
		CauseOfDeath:           req.CauseOfDeath,
		AgeAtDeath:             req.AgeAtDeath,
	}
}

// UpdateToDomainFamilyHistory updates existing domain model with request data
func UpdateToDomainFamilyHistory(existing patients.PatientFamilyHistory, req UpdateFamilyHistoryRequest) patients.PatientFamilyHistory {
	existing.Relative = req.Relative
	existing.RelativeAgeAtDiagnosis = req.RelativeAgeAtDiagnosis
	existing.ConditionName = req.ConditionName
	existing.Notes = req.Notes
	existing.IsAlive = req.IsAlive
	existing.CauseOfDeath = req.CauseOfDeath
	existing.AgeAtDeath = req.AgeAtDeath
	return existing
}
