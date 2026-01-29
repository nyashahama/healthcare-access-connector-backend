package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientMedication represents medication records
type PatientMedication struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	MedicationName      string     `json:"medication_name"`
	GenericName         *string    `json:"generic_name,omitempty"`
	Dosage              *string    `json:"dosage,omitempty"`    // "2 puffs", "500mg", etc.
	Frequency           *string    `json:"frequency,omitempty"` // "daily", "twice daily", "as needed"
	Route               *string    `json:"route,omitempty"`     // "oral", "inhalation", "topical", "injection"
	PrescribingDoctor   *string    `json:"prescribing_doctor,omitempty"`
	PharmacyName        *string    `json:"pharmacy_name,omitempty"`
	PrescriptionDate    *time.Time `json:"prescription_date,omitempty"`
	StartDate           *time.Time `json:"start_date,omitempty"`
	EndDate             *time.Time `json:"end_date,omitempty"`
	ReasonForMedication *string    `json:"reason_for_medication,omitempty"`
	Status              string     `json:"status"` // 'active', 'completed', 'discontinued'
	SideEffects         *string    `json:"side_effects,omitempty"`
	Instructions        *string    `json:"instructions,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// MedicationStatistics provides medication statistics for a patient
type MedicationStatistics struct {
	TotalMedications  int64 `json:"total_medications"`
	ActiveMedications int64 `json:"active_medications"`
	WithSideEffects   int64 `json:"with_side_effects"`
	PrescriberCount   int64 `json:"prescriber_count"`
}

// MedicationSystemMetrics provides system-wide medication metrics
type MedicationSystemMetrics struct {
	PatientsOnMedication int64   `json:"patients_on_medication"`
	TotalPrescriptions   int64   `json:"total_prescriptions"`
	ActivePrescriptions  int64   `json:"active_prescriptions"`
	WithSideEffects      int64   `json:"with_side_effects"`
	UniqueMedications    int64   `json:"unique_medications"`
	AvgDurationDays      float64 `json:"avg_duration_days"`
}

// MedicationDistribution represents medication usage distribution
type MedicationDistribution struct {
	MedicationName      string `json:"medication_name"`
	PatientCount        int64  `json:"patient_count"`
	ActivePrescriptions int64  `json:"active_prescriptions"`
	ReportedSideEffects int64  `json:"reported_side_effects"`
}

// PrescriptionTrend represents prescription trends over time
type PrescriptionTrend struct {
	Month             time.Time `json:"month"`
	PrescriptionCount int64     `json:"prescription_count"`
	UniquePatients    int64     `json:"unique_patients"`
	UniqueMedications int64     `json:"unique_medications"`
}
