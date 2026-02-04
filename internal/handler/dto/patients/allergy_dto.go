package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateAllergyRequest represents a request to create an allergy record
type CreateAllergyRequest struct {
	PatientID           uuid.UUID  `json:"patient_id"`
	AllergyName         string     `json:"allergy_name"`
	Severity            string     `json:"severity"`
	ReactionDescription *string    `json:"reaction_description,omitempty"`
	FirstIdentifiedDate *time.Time `json:"first_identified_date,omitempty"`
	LastOccurrenceDate  *time.Time `json:"last_occurrence_date,omitempty"`
	Status              string     `json:"status"`
	Notes               *string    `json:"notes,omitempty"`
}

// UpdateAllergyRequest represents a request to update an allergy record
type UpdateAllergyRequest struct {
	AllergyName         string     `json:"allergy_name"`
	Severity            string     `json:"severity"`
	ReactionDescription *string    `json:"reaction_description,omitempty"`
	FirstIdentifiedDate *time.Time `json:"first_identified_date,omitempty"`
	LastOccurrenceDate  *time.Time `json:"last_occurrence_date,omitempty"`
	Status              string     `json:"status"`
	Notes               *string    `json:"notes,omitempty"`
}

// AllergyResponse represents an allergy record in responses
type AllergyResponse struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	AllergyName         string     `json:"allergy_name"`
	Severity            string     `json:"severity"`
	ReactionDescription *string    `json:"reaction_description,omitempty"`
	FirstIdentifiedDate *time.Time `json:"first_identified_date,omitempty"`
	LastOccurrenceDate  *time.Time `json:"last_occurrence_date,omitempty"`
	Status              string     `json:"status"`
	Notes               *string    `json:"notes,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// AllergiesListResponse represents a list of allergies
type AllergiesListResponse struct {
	Allergies []AllergyResponse `json:"allergies"`
	Count     int               `json:"count"`
}

// ToAllergyResponse converts domain PatientAllergy to response DTO
func ToAllergyResponse(allergy patients.PatientAllergy) AllergyResponse {
	return AllergyResponse{
		ID:                  allergy.ID,
		PatientID:           allergy.PatientID,
		AllergyName:         allergy.AllergyName,
		Severity:            allergy.Severity,
		ReactionDescription: allergy.ReactionDescription,
		FirstIdentifiedDate: allergy.FirstIdentifiedDate,
		LastOccurrenceDate:  allergy.LastOccurrenceDate,
		Status:              allergy.Status,
		Notes:               allergy.Notes,
		CreatedAt:           allergy.CreatedAt,
		UpdatedAt:           allergy.UpdatedAt,
	}
}

// ToDomainAllergy converts request DTO to domain model
func ToDomainAllergy(req CreateAllergyRequest) patients.PatientAllergy {
	return patients.PatientAllergy{
		PatientID:           req.PatientID,
		AllergyName:         req.AllergyName,
		Severity:            req.Severity,
		ReactionDescription: req.ReactionDescription,
		FirstIdentifiedDate: req.FirstIdentifiedDate,
		LastOccurrenceDate:  req.LastOccurrenceDate,
		Status:              req.Status,
		Notes:               req.Notes,
	}
}

// UpdateToDomainAllergy updates existing domain model with request data
func UpdateToDomainAllergy(existing patients.PatientAllergy, req UpdateAllergyRequest) patients.PatientAllergy {
	existing.AllergyName = req.AllergyName
	existing.Severity = req.Severity
	existing.ReactionDescription = req.ReactionDescription
	existing.FirstIdentifiedDate = req.FirstIdentifiedDate
	existing.LastOccurrenceDate = req.LastOccurrenceDate
	existing.Status = req.Status
	existing.Notes = req.Notes
	return existing
}
