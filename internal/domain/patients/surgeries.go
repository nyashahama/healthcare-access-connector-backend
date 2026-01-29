package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientSurgery represents surgical history
type PatientSurgery struct {
	ID             uuid.UUID `json:"id"`
	PatientID      uuid.UUID `json:"patient_id"`
	ProcedureName  string    `json:"procedure_name"`
	ProcedureDate  time.Time `json:"procedure_date"`
	HospitalName   *string   `json:"hospital_name,omitempty"`
	SurgeonName    *string   `json:"surgeon_name,omitempty"`
	AnesthesiaType *string   `json:"anesthesia_type,omitempty"`
	Complications  *string   `json:"complications,omitempty"`
	RecoveryNotes  *string   `json:"recovery_notes,omitempty"`
	Outcome        *string   `json:"outcome,omitempty"` // 'successful', 'partial_success', 'complications'
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SurgeryStatistics provides surgical history statistics
type SurgeryStatistics struct {
	TotalSurgeries           int64      `json:"total_surgeries"`
	WithComplications        int64      `json:"with_complications"`
	Successful               int64      `json:"successful"`
	WithOutcomeComplications int64      `json:"with_outcome_complications"`
	LastSurgeryDate          *time.Time `json:"last_surgery_date,omitempty"`
}

// SurgerySystemMetrics provides system-wide surgery metrics
type SurgerySystemMetrics struct {
	PatientsWithSurgeries      int64   `json:"patients_with_surgeries"`
	TotalSurgeries             int64   `json:"total_surgeries"`
	SuccessfulSurgeries        int64   `json:"successful_surgeries"`
	SurgeriesWithComplications int64   `json:"surgeries_with_complications"`
	UniqueProcedures           int64   `json:"unique_procedures"`
	HospitalsUsed              int64   `json:"hospitals_used"`
	AvgYearsSinceSurgery       float64 `json:"avg_years_since_surgery"`
}

// ProcedureStats represents statistics for a specific procedure
type ProcedureStats struct {
	ProcedureName     string `json:"procedure_name"`
	PatientCount      int64  `json:"patient_count"`
	TotalProcedures   int64  `json:"total_procedures"`
	SuccessfulCount   int64  `json:"successful_count"`
	ComplicationCount int64  `json:"complication_count"`
}

// SurgeryTrend represents surgical trends over time
type SurgeryTrend struct {
	Year             time.Time `json:"year"`
	SurgeryCount     int64     `json:"surgery_count"`
	UniquePatients   int64     `json:"unique_patients"`
	UniqueProcedures int64     `json:"unique_procedures"`
}
