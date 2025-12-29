package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientMedication represents a patient medication
type PatientMedication struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	MedicationName      string     `json:"medication_name"`
	GenericName         *string    `json:"generic_name,omitempty"`
	Dosage              *string    `json:"dosage,omitempty"`
	Frequency           *string    `json:"frequency,omitempty"`
	Route               *string    `json:"route,omitempty"`
	PrescribingDoctor   *string    `json:"prescribing_doctor,omitempty"`
	PharmacyName        *string    `json:"pharmacy_name,omitempty"`
	PrescriptionDate    *time.Time `json:"prescription_date,omitempty"`
	StartDate           *time.Time `json:"start_date,omitempty"`
	EndDate             *time.Time `json:"end_date,omitempty"`
	ReasonForMedication *string    `json:"reason_for_medication,omitempty"`
	Status              string     `json:"status"` // active, completed, discontinued
	SideEffects         *string    `json:"side_effects,omitempty"`
	Instructions        *string    `json:"instructions,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}