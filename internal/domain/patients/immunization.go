package patients

import (
	"time"

	"github.com/google/uuid"
)

// PatientImmunization represents a vaccination record
type PatientImmunization struct {
	ID                 uuid.UUID  `json:"id"`
	PatientID          uuid.UUID  `json:"patient_id"`
	VaccineName        string     `json:"vaccine_name"`
	VaccineType        *string    `json:"vaccine_type,omitempty"` // routine, travel, covid, flu
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