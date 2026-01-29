package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientFamilyHistory represents family medical history
type PatientFamilyHistory struct {
	ID                     uuid.UUID `json:"id"`
	PatientID              uuid.UUID `json:"patient_id"`
	Relative               string    `json:"relative"` // 'mother', 'father', 'sibling', 'grandparent'
	RelativeAgeAtDiagnosis *int      `json:"relative_age_at_diagnosis,omitempty"`
	ConditionName          string    `json:"condition_name"`
	Notes                  *string   `json:"notes,omitempty"`
	IsAlive                *bool     `json:"is_alive,omitempty"`
	CauseOfDeath           *string   `json:"cause_of_death,omitempty"`
	AgeAtDeath             *int      `json:"age_at_death,omitempty"`
	CreatedAt              time.Time `json:"created_at"`
}

// FamilyHistoryStatistics provides family history statistics
type FamilyHistoryStatistics struct {
	TotalEntries      int64 `json:"total_entries"`
	UniqueRelatives   int64 `json:"unique_relatives"`
	UniqueConditions  int64 `json:"unique_conditions"`
	DeceasedRelatives int64 `json:"deceased_relatives"`
}

// FamilyHistorySystemMetrics provides system-wide family history metrics
type FamilyHistorySystemMetrics struct {
	PatientsWithFamilyHistory int64   `json:"patients_with_family_history"`
	TotalEntries              int64   `json:"total_entries"`
	UniqueConditions          int64   `json:"unique_conditions"`
	DeceasedCount             int64   `json:"deceased_count"`
	AvgAgeAtDeath             float64 `json:"avg_age_at_death"`
}

// GeneticConditionRisk represents genetic condition risk assessment
type GeneticConditionRisk struct {
	ConditionName     string   `json:"condition_name"`
	AffectedRelatives int64    `json:"affected_relatives"`
	Relatives         string   `json:"relatives"`
	AvgOnsetAge       *float64 `json:"avg_onset_age,omitempty"`
}

// FamilyConditionStats represents statistics for family conditions
type FamilyConditionStats struct {
	ConditionName   string   `json:"condition_name"`
	OccurrenceCount int64    `json:"occurrence_count"`
	PatientCount    int64    `json:"patient_count"`
	AvgOnsetAge     *float64 `json:"avg_onset_age,omitempty"`
}
