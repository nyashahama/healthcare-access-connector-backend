package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateSurgeryRequest represents a request to create a surgery record
type CreateSurgeryRequest struct {
	PatientID      uuid.UUID `json:"patient_id"`
	ProcedureName  string    `json:"procedure_name"`
	ProcedureDate  time.Time `json:"procedure_date"`
	HospitalName   *string   `json:"hospital_name,omitempty"`
	SurgeonName    *string   `json:"surgeon_name,omitempty"`
	AnesthesiaType *string   `json:"anesthesia_type,omitempty"`
	Complications  *string   `json:"complications,omitempty"`
	RecoveryNotes  *string   `json:"recovery_notes,omitempty"`
	Outcome        *string   `json:"outcome,omitempty"`
}

// UpdateSurgeryRequest represents a request to update a surgery record
type UpdateSurgeryRequest struct {
	ProcedureName  string    `json:"procedure_name"`
	ProcedureDate  time.Time `json:"procedure_date"`
	HospitalName   *string   `json:"hospital_name,omitempty"`
	SurgeonName    *string   `json:"surgeon_name,omitempty"`
	AnesthesiaType *string   `json:"anesthesia_type,omitempty"`
	Complications  *string   `json:"complications,omitempty"`
	RecoveryNotes  *string   `json:"recovery_notes,omitempty"`
	Outcome        *string   `json:"outcome,omitempty"`
}

// SurgeryResponse represents a surgery record in responses
type SurgeryResponse struct {
	ID             uuid.UUID `json:"id"`
	PatientID      uuid.UUID `json:"patient_id"`
	ProcedureName  string    `json:"procedure_name"`
	ProcedureDate  time.Time `json:"procedure_date"`
	HospitalName   *string   `json:"hospital_name,omitempty"`
	SurgeonName    *string   `json:"surgeon_name,omitempty"`
	AnesthesiaType *string   `json:"anesthesia_type,omitempty"`
	Complications  *string   `json:"complications,omitempty"`
	RecoveryNotes  *string   `json:"recovery_notes,omitempty"`
	Outcome        *string   `json:"outcome,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// SurgeriesListResponse represents a list of surgeries
type SurgeriesListResponse struct {
	Surgeries []SurgeryResponse `json:"surgeries"`
	Count     int               `json:"count"`
}

// ToSurgeryResponse converts domain PatientSurgery to response DTO
func ToSurgeryResponse(surgery patients.PatientSurgery) SurgeryResponse {
	return SurgeryResponse{
		ID:             surgery.ID,
		PatientID:      surgery.PatientID,
		ProcedureName:  surgery.ProcedureName,
		ProcedureDate:  surgery.ProcedureDate,
		HospitalName:   surgery.HospitalName,
		SurgeonName:    surgery.SurgeonName,
		AnesthesiaType: surgery.AnesthesiaType,
		Complications:  surgery.Complications,
		RecoveryNotes:  surgery.RecoveryNotes,
		Outcome:        surgery.Outcome,
		CreatedAt:      surgery.CreatedAt,
		UpdatedAt:      surgery.UpdatedAt,
	}
}

// ToDomainSurgery converts request DTO to domain model
func ToDomainSurgery(req CreateSurgeryRequest) patients.PatientSurgery {
	return patients.PatientSurgery{
		PatientID:      req.PatientID,
		ProcedureName:  req.ProcedureName,
		ProcedureDate:  req.ProcedureDate,
		HospitalName:   req.HospitalName,
		SurgeonName:    req.SurgeonName,
		AnesthesiaType: req.AnesthesiaType,
		Complications:  req.Complications,
		RecoveryNotes:  req.RecoveryNotes,
		Outcome:        req.Outcome,
	}
}

// UpdateToDomainSurgery updates existing domain model with request data
func UpdateToDomainSurgery(existing patients.PatientSurgery, req UpdateSurgeryRequest) patients.PatientSurgery {
	existing.ProcedureName = req.ProcedureName
	existing.ProcedureDate = req.ProcedureDate
	existing.HospitalName = req.HospitalName
	existing.SurgeonName = req.SurgeonName
	existing.AnesthesiaType = req.AnesthesiaType
	existing.Complications = req.Complications
	existing.RecoveryNotes = req.RecoveryNotes
	existing.Outcome = req.Outcome
	return existing
}
