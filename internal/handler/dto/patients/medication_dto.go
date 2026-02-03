package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateMedicationRequest represents a request to create a medication record
type CreateMedicationRequest struct {
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
	Status              string     `json:"status"`
	SideEffects         *string    `json:"side_effects,omitempty"`
	Instructions        *string    `json:"instructions,omitempty"`
}

// UpdateMedicationRequest represents a request to update a medication record
type UpdateMedicationRequest struct {
	MedicationName string     `json:"medication_name"`
	GenericName    *string    `json:"generic_name,omitempty"`
	Dosage         *string    `json:"dosage,omitempty"`
	Frequency      *string    `json:"frequency,omitempty"`
	Route          *string    `json:"route,omitempty"`
	EndDate        *time.Time `json:"end_date,omitempty"`
	Status         string     `json:"status"`
	SideEffects    *string    `json:"side_effects,omitempty"`
	Instructions   *string    `json:"instructions,omitempty"`
}

// MedicationResponse represents a medication record in responses
type MedicationResponse struct {
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
	Status              string     `json:"status"`
	SideEffects         *string    `json:"side_effects,omitempty"`
	Instructions        *string    `json:"instructions,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// MedicationsListResponse represents a list of medications
type MedicationsListResponse struct {
	Medications []MedicationResponse `json:"medications"`
	Count       int                  `json:"count"`
}

// ToMedicationResponse converts domain PatientMedication to response DTO
func ToMedicationResponse(medication patients.PatientMedication) MedicationResponse {
	return MedicationResponse{
		ID:                  medication.ID,
		PatientID:           medication.PatientID,
		MedicationName:      medication.MedicationName,
		GenericName:         medication.GenericName,
		Dosage:              medication.Dosage,
		Frequency:           medication.Frequency,
		Route:               medication.Route,
		PrescribingDoctor:   medication.PrescribingDoctor,
		PharmacyName:        medication.PharmacyName,
		PrescriptionDate:    medication.PrescriptionDate,
		StartDate:           medication.StartDate,
		EndDate:             medication.EndDate,
		ReasonForMedication: medication.ReasonForMedication,
		Status:              medication.Status,
		SideEffects:         medication.SideEffects,
		Instructions:        medication.Instructions,
		CreatedAt:           medication.CreatedAt,
		UpdatedAt:           medication.UpdatedAt,
	}
}

// ToDomainMedication converts request DTO to domain model
func ToDomainMedication(req CreateMedicationRequest) patients.PatientMedication {
	return patients.PatientMedication{
		PatientID:           req.PatientID,
		MedicationName:      req.MedicationName,
		GenericName:         req.GenericName,
		Dosage:              req.Dosage,
		Frequency:           req.Frequency,
		Route:               req.Route,
		PrescribingDoctor:   req.PrescribingDoctor,
		PharmacyName:        req.PharmacyName,
		PrescriptionDate:    req.PrescriptionDate,
		StartDate:           req.StartDate,
		EndDate:             req.EndDate,
		ReasonForMedication: req.ReasonForMedication,
		Status:              req.Status,
		SideEffects:         req.SideEffects,
		Instructions:        req.Instructions,
	}
}

// UpdateToDomainMedication updates existing domain model with request data
func UpdateToDomainMedication(existing patients.PatientMedication, req UpdateMedicationRequest) patients.PatientMedication {
	existing.MedicationName = req.MedicationName
	existing.GenericName = req.GenericName
	existing.Dosage = req.Dosage
	existing.Frequency = req.Frequency
	existing.Route = req.Route
	existing.EndDate = req.EndDate
	existing.Status = req.Status
	existing.SideEffects = req.SideEffects
	existing.Instructions = req.Instructions
	return existing
}
