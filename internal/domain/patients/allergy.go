package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientAllergy represents an allergy record
type PatientAllergy struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	AllergyName         string     `json:"allergy_name"`
	Severity            string     `json:"severity"` // 'mild', 'moderate', 'severe', 'life_threatening'
	ReactionDescription *string    `json:"reaction_description,omitempty"`
	FirstIdentifiedDate *time.Time `json:"first_identified_date,omitempty"`
	LastOccurrenceDate  *time.Time `json:"last_occurrence_date,omitempty"`
	Status              string     `json:"status"` // 'active', 'resolved', 'inactive'
	Notes               *string    `json:"notes,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// AllergyStatistics provides statistics for a patient's allergies
type AllergyStatistics struct {
	TotalAllergies  int64 `json:"total_allergies"`
	ActiveAllergies int64 `json:"active_allergies"`
	LifeThreatening int64 `json:"life_threatening"`
	Severe          int64 `json:"severe"`
	Moderate        int64 `json:"moderate"`
	Mild            int64 `json:"mild"`
}

// AllergySystemMetrics provides system-wide allergy metrics
type AllergySystemMetrics struct {
	TotalPatientsWithAllergies  int64   `json:"total_patients_with_allergies"`
	TotalAllergies              int64   `json:"total_allergies"`
	ActiveAllergies             int64   `json:"active_allergies"`
	LifeThreateningCount        int64   `json:"life_threatening_count"`
	SevereCount                 int64   `json:"severe_count"`
	AvgYearsSinceIdentification float64 `json:"avg_years_since_identification"`
}

// AllergySeverityDistribution represents distribution by severity
type AllergySeverityDistribution struct {
	Severity     string `json:"severity"`
	AllergyCount int64  `json:"allergy_count"`
	PatientCount int64  `json:"patient_count"`
}

// AllergyDistribution represents common allergies
type AllergyDistribution struct {
	AllergyName  string `json:"allergy_name"`
	PatientCount int64  `json:"patient_count"`
	SevereCases  int64  `json:"severe_cases"`
}

// CriticalAllergyWarnings contains critical allergy information
type CriticalAllergyWarnings struct {
	LifeThreateningCount int64   `json:"life_threatening_count"`
	SevereCount          int64   `json:"severe_count"`
	CriticalAllergies    *string `json:"critical_allergies,omitempty"`
}
