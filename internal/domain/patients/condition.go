package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientCondition represents a medical condition
type PatientCondition struct {
	ID              uuid.UUID  `json:"id"`
	PatientID       uuid.UUID  `json:"patient_id"`
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"` // 'chronic', 'acute', 'genetic', 'mental_health'
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"` // 'mild', 'moderate', 'severe'
	Status          string     `json:"status"`             // 'active', 'resolved', 'remission', 'managed'
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ConditionStatistics provides statistics for a patient's conditions
type ConditionStatistics struct {
	TotalConditions   int64 `json:"total_conditions"`
	ActiveConditions  int64 `json:"active_conditions"`
	ChronicConditions int64 `json:"chronic_conditions"`
	SevereConditions  int64 `json:"severe_conditions"`
}

// ConditionSystemMetrics provides system-wide condition metrics
type ConditionSystemMetrics struct {
	PatientsWithConditions int64   `json:"patients_with_conditions"`
	TotalConditions        int64   `json:"total_conditions"`
	ActiveConditions       int64   `json:"active_conditions"`
	ChronicConditions      int64   `json:"chronic_conditions"`
	AcuteConditions        int64   `json:"acute_conditions"`
	SevereConditions       int64   `json:"severe_conditions"`
	AvgYearsSinceDiagnosis float64 `json:"avg_years_since_diagnosis"`
}

// ConditionDistribution represents condition prevalence
type ConditionDistribution struct {
	ConditionName string `json:"condition_name"`
	PatientCount  int64  `json:"patient_count"`
	SevereCases   int64  `json:"severe_cases"`
	ActiveCases   int64  `json:"active_cases"`
}

// ConditionTypeDistribution represents distribution by condition type
type ConditionTypeDistribution struct {
	Type             string  `json:"type"`
	ConditionCount   int64   `json:"condition_count"`
	PatientCount     int64   `json:"patient_count"`
	AvgDurationYears float64 `json:"avg_duration_years"`
}
