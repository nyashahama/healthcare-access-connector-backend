package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientImmunization represents immunization records
type PatientImmunization struct {
	ID                 uuid.UUID  `json:"id"`
	PatientID          uuid.UUID  `json:"patient_id"`
	VaccineName        string     `json:"vaccine_name"`
	VaccineType        *string    `json:"vaccine_type,omitempty"` // 'routine', 'travel', 'covid', 'flu'
	AdministrationDate time.Time  `json:"administration_date"`
	NextDueDate        *time.Time `json:"next_due_date,omitempty"`
	AdministeredBy     *string    `json:"administered_by,omitempty"`
	ClinicName         *string    `json:"clinic_name,omitempty"`
	LotNumber          *string    `json:"lot_number,omitempty"`
	Manufacturer       *string    `json:"manufacturer,omitempty"`
	DoseNumber         *int       `json:"dose_number,omitempty"`
	TotalDoses         *int       `json:"total_doses,omitempty"`
	Notes              *string    `json:"notes,omitempty"`
	DocumentedBy       *uuid.UUID `json:"documented_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// ImmunizationStatistics provides immunization statistics for a patient
type ImmunizationStatistics struct {
	TotalImmunizations int64 `json:"total_immunizations"`
	UniqueVaccines     int64 `json:"unique_vaccines"`
	RoutineCount       int64 `json:"routine_count"`
	UpcomingCount      int64 `json:"upcoming_count"`
	OverdueCount       int64 `json:"overdue_count"`
}

// ImmunizationSystemMetrics provides system-wide immunization metrics
type ImmunizationSystemMetrics struct {
	PatientsImmunized    int64   `json:"patients_immunized"`
	TotalImmunizations   int64   `json:"total_immunizations"`
	UniqueVaccines       int64   `json:"unique_vaccines"`
	RoutineImmunizations int64   `json:"routine_immunizations"`
	CovidImmunizations   int64   `json:"covid_immunizations"`
	FluImmunizations     int64   `json:"flu_immunizations"`
	OverdueCount         int64   `json:"overdue_count"`
	AvgSeriesCompletion  float64 `json:"avg_series_completion"`
}

// VaccineDistribution represents vaccine usage distribution
type VaccineDistribution struct {
	VaccineName   string  `json:"vaccine_name"`
	PatientCount  int64   `json:"patient_count"`
	TotalDoses    int64   `json:"total_doses"`
	AvgDoseNumber float64 `json:"avg_dose_number"`
}

// VaccineCoverage represents immunization coverage by type
type VaccineCoverage struct {
	VaccineType        string `json:"vaccine_type"`
	PatientsVaccinated int64  `json:"patients_vaccinated"`
	TotalDoses         int64  `json:"total_doses"`
	DosesLastYear      int64  `json:"doses_last_year"`
}

// VaccineSeriesProgress represents progress on vaccine series
type VaccineSeriesProgress struct {
	VaccineName  string     `json:"vaccine_name"`
	CurrentDose  int        `json:"current_dose"`
	TotalDoses   int        `json:"total_doses"`
	Status       string     `json:"status"` // 'complete', 'incomplete'
	LastDoseDate *time.Time `json:"last_dose_date,omitempty"`
	NextDue      *time.Time `json:"next_due,omitempty"`
}
