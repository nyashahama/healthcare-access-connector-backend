package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateImmunizationRequest represents a request to create an immunization record
type CreateImmunizationRequest struct {
	PatientID          uuid.UUID  `json:"patient_id"`
	VaccineName        string     `json:"vaccine_name"`
	VaccineType        *string    `json:"vaccine_type,omitempty"`
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
}

// UpdateImmunizationRequest represents a request to update an immunization record
type UpdateImmunizationRequest struct {
	VaccineName        string     `json:"vaccine_name"`
	VaccineType        *string    `json:"vaccine_type,omitempty"`
	AdministrationDate time.Time  `json:"administration_date"`
	NextDueDate        *time.Time `json:"next_due_date,omitempty"`
	AdministeredBy     *string    `json:"administered_by,omitempty"`
	ClinicName         *string    `json:"clinic_name,omitempty"`
	LotNumber          *string    `json:"lot_number,omitempty"`
	Manufacturer       *string    `json:"manufacturer,omitempty"`
	DoseNumber         *int       `json:"dose_number,omitempty"`
	TotalDoses         *int       `json:"total_doses,omitempty"`
	Notes              *string    `json:"notes,omitempty"`
}

// ImmunizationResponse represents an immunization record in responses
type ImmunizationResponse struct {
	ID                 uuid.UUID  `json:"id"`
	PatientID          uuid.UUID  `json:"patient_id"`
	VaccineName        string     `json:"vaccine_name"`
	VaccineType        *string    `json:"vaccine_type,omitempty"`
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

// ImmunizationsListResponse represents a list of immunizations
type ImmunizationsListResponse struct {
	Immunizations []ImmunizationResponse `json:"immunizations"`
	Count         int                    `json:"count"`
}

// ToImmunizationResponse converts domain PatientImmunization to response DTO
func ToImmunizationResponse(immunization patients.PatientImmunization) ImmunizationResponse {
	return ImmunizationResponse{
		ID:                 immunization.ID,
		PatientID:          immunization.PatientID,
		VaccineName:        immunization.VaccineName,
		VaccineType:        immunization.VaccineType,
		AdministrationDate: immunization.AdministrationDate,
		NextDueDate:        immunization.NextDueDate,
		AdministeredBy:     immunization.AdministeredBy,
		ClinicName:         immunization.ClinicName,
		LotNumber:          immunization.LotNumber,
		Manufacturer:       immunization.Manufacturer,
		DoseNumber:         immunization.DoseNumber,
		TotalDoses:         immunization.TotalDoses,
		Notes:              immunization.Notes,
		DocumentedBy:       immunization.DocumentedBy,
		CreatedAt:          immunization.CreatedAt,
		UpdatedAt:          immunization.UpdatedAt,
	}
}

// ToDomainImmunization converts request DTO to domain model
func ToDomainImmunization(req CreateImmunizationRequest) patients.PatientImmunization {
	return patients.PatientImmunization{
		PatientID:          req.PatientID,
		VaccineName:        req.VaccineName,
		VaccineType:        req.VaccineType,
		AdministrationDate: req.AdministrationDate,
		NextDueDate:        req.NextDueDate,
		AdministeredBy:     req.AdministeredBy,
		ClinicName:         req.ClinicName,
		LotNumber:          req.LotNumber,
		Manufacturer:       req.Manufacturer,
		DoseNumber:         req.DoseNumber,
		TotalDoses:         req.TotalDoses,
		Notes:              req.Notes,
		DocumentedBy:       req.DocumentedBy,
	}
}

// UpdateToDomainImmunization updates existing domain model with request data
func UpdateToDomainImmunization(existing patients.PatientImmunization, req UpdateImmunizationRequest) patients.PatientImmunization {
	existing.VaccineName = req.VaccineName
	existing.VaccineType = req.VaccineType
	existing.AdministrationDate = req.AdministrationDate
	existing.NextDueDate = req.NextDueDate
	existing.AdministeredBy = req.AdministeredBy
	existing.ClinicName = req.ClinicName
	existing.LotNumber = req.LotNumber
	existing.Manufacturer = req.Manufacturer
	existing.DoseNumber = req.DoseNumber
	existing.TotalDoses = req.TotalDoses
	existing.Notes = req.Notes
	return existing
}
