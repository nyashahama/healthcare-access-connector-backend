package patients

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
)

// CreateDependentHealthRecordRequest represents a request to create a dependent health record
type CreateDependentHealthRecordRequest struct {
	DependentID         uuid.UUID   `json:"dependent_id"`
	RecordType          *string     `json:"record_type,omitempty"`
	RecordDate          time.Time   `json:"record_date"`
	WeightKg            *float64    `json:"weight_kg,omitempty"`
	HeightCm            *float64    `json:"height_cm,omitempty"`
	HeadCircumferenceCm *float64    `json:"head_circumference_cm,omitempty"`
	TemperatureC        *float64    `json:"temperature_c,omitempty"`
	Notes               *string     `json:"notes,omitempty"`
	ProviderName        *string     `json:"provider_name,omitempty"`
	ClinicName          *string     `json:"clinic_name,omitempty"`
	NextAppointmentDate *time.Time  `json:"next_appointment_date,omitempty"`
	Documents           interface{} `json:"documents,omitempty"`
}

// UpdateDependentHealthRecordRequest represents a request to update a dependent health record
type UpdateDependentHealthRecordRequest struct {
	RecordType          *string     `json:"record_type,omitempty"`
	RecordDate          time.Time   `json:"record_date"`
	WeightKg            *float64    `json:"weight_kg,omitempty"`
	HeightCm            *float64    `json:"height_cm,omitempty"`
	HeadCircumferenceCm *float64    `json:"head_circumference_cm,omitempty"`
	TemperatureC        *float64    `json:"temperature_c,omitempty"`
	Notes               *string     `json:"notes,omitempty"`
	ProviderName        *string     `json:"provider_name,omitempty"`
	ClinicName          *string     `json:"clinic_name,omitempty"`
	NextAppointmentDate *time.Time  `json:"next_appointment_date,omitempty"`
	Documents           interface{} `json:"documents,omitempty"`
}

// DependentHealthRecordResponse represents a dependent health record in responses
type DependentHealthRecordResponse struct {
	ID                  uuid.UUID   `json:"id"`
	DependentID         uuid.UUID   `json:"dependent_id"`
	RecordType          *string     `json:"record_type,omitempty"`
	RecordDate          time.Time   `json:"record_date"`
	WeightKg            *float64    `json:"weight_kg,omitempty"`
	HeightCm            *float64    `json:"height_cm,omitempty"`
	HeadCircumferenceCm *float64    `json:"head_circumference_cm,omitempty"`
	TemperatureC        *float64    `json:"temperature_c,omitempty"`
	Notes               *string     `json:"notes,omitempty"`
	ProviderName        *string     `json:"provider_name,omitempty"`
	ClinicName          *string     `json:"clinic_name,omitempty"`
	NextAppointmentDate *time.Time  `json:"next_appointment_date,omitempty"`
	Documents           interface{} `json:"documents,omitempty"`
	CreatedAt           time.Time   `json:"created_at"`
}

// DependentHealthRecordsListResponse represents a list of dependent health records
type DependentHealthRecordsListResponse struct {
	HealthRecords []DependentHealthRecordResponse `json:"health_records"`
	Count         int                             `json:"count"`
}

// ToDependentHealthRecordResponse converts domain DependentHealthRecord to response DTO
func ToDependentHealthRecordResponse(record patients.DependentHealthRecord) DependentHealthRecordResponse {
	return DependentHealthRecordResponse{
		ID:                  record.ID,
		DependentID:         record.DependentID,
		RecordType:          record.RecordType,
		RecordDate:          record.RecordDate,
		WeightKg:            record.WeightKg,
		HeightCm:            record.HeightCm,
		HeadCircumferenceCm: record.HeadCircumferenceCm,
		TemperatureC:        record.TemperatureC,
		Notes:               record.Notes,
		ProviderName:        record.ProviderName,
		ClinicName:          record.ClinicName,
		NextAppointmentDate: record.NextAppointmentDate,
		Documents:           record.Documents,
		CreatedAt:           record.CreatedAt,
	}
}

// ToDomainDependentHealthRecord converts request DTO to domain model
func ToDomainDependentHealthRecord(req CreateDependentHealthRecordRequest) patients.DependentHealthRecord {
	return patients.DependentHealthRecord{
		DependentID:         req.DependentID,
		RecordType:          req.RecordType,
		RecordDate:          req.RecordDate,
		WeightKg:            req.WeightKg,
		HeightCm:            req.HeightCm,
		HeadCircumferenceCm: req.HeadCircumferenceCm,
		TemperatureC:        req.TemperatureC,
		Notes:               req.Notes,
		ProviderName:        req.ProviderName,
		ClinicName:          req.ClinicName,
		NextAppointmentDate: req.NextAppointmentDate,
		Documents:           req.Documents,
	}
}

// UpdateToDomainDependentHealthRecord updates existing domain model with request data
func UpdateToDomainDependentHealthRecord(existing patients.DependentHealthRecord, req UpdateDependentHealthRecordRequest) patients.DependentHealthRecord {
	existing.RecordType = req.RecordType
	existing.RecordDate = req.RecordDate
	existing.WeightKg = req.WeightKg
	existing.HeightCm = req.HeightCm
	existing.HeadCircumferenceCm = req.HeadCircumferenceCm
	existing.TemperatureC = req.TemperatureC
	existing.Notes = req.Notes
	existing.ProviderName = req.ProviderName
	existing.ClinicName = req.ClinicName
	existing.NextAppointmentDate = req.NextAppointmentDate
	existing.Documents = req.Documents
	return existing
}
