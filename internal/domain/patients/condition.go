package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientCondition represents a patient medical condition
type PatientCondition struct {
	ID              uuid.UUID  `json:"id"`
	PatientID       uuid.UUID  `json:"patient_id"`
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"` // chronic, acute, genetic, mental_health
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"` // mild, moderate, severe
	Status          string     `json:"status"`             // active, resolved, remission, managed
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}