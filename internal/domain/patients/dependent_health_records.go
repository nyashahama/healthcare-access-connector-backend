package patients

import (
	"time"

	"github.com/google/uuid"
)

// DependentHealthRecord represents a health record for a dependent
type DependentHealthRecord struct {
	ID                  uuid.UUID   `json:"id"`
	DependentID         uuid.UUID   `json:"dependent_id"`
	RecordType          *string     `json:"record_type,omitempty"` // 'growth_check', 'vaccination', 'checkup', 'emergency'
	RecordDate          time.Time   `json:"record_date"`
	WeightKg            *float64    `json:"weight_kg,omitempty"`
	HeightCm            *float64    `json:"height_cm,omitempty"`
	HeadCircumferenceCm *float64    `json:"head_circumference_cm,omitempty"`
	TemperatureC        *float64    `json:"temperature_c,omitempty"`
	Notes               *string     `json:"notes,omitempty"`
	ProviderName        *string     `json:"provider_name,omitempty"`
	ClinicName          *string     `json:"clinic_name,omitempty"`
	NextAppointmentDate *time.Time  `json:"next_appointment_date,omitempty"`
	Documents           interface{} `json:"documents,omitempty"` // JSONB - store as interface{} or map[string]interface{}
	CreatedAt           time.Time   `json:"created_at"`
}

// GrowthMeasurement represents a growth measurement snapshot
type GrowthMeasurement struct {
	WeightKg            *float64  `json:"weight_kg,omitempty"`
	HeightCm            *float64  `json:"height_cm,omitempty"`
	HeadCircumferenceCm *float64  `json:"head_circumference_cm,omitempty"`
	RecordDate          time.Time `json:"record_date"`
}

// VitalHistory represents a historical vital sign record
type VitalHistory struct {
	RecordDate time.Time `json:"record_date"`
	Value      float64   `json:"value"`
	RecordType *string   `json:"record_type,omitempty"`
	Notes      *string   `json:"notes,omitempty"`
}

// HealthRecordStatistics provides statistics for dependent health records
type HealthRecordStatistics struct {
	TotalRecords    int64      `json:"total_records"`
	GrowthChecks    int64      `json:"growth_checks"`
	Vaccinations    int64      `json:"vaccinations"`
	Checkups        int64      `json:"checkups"`
	EmergencyVisits int64      `json:"emergency_visits"`
	LastRecordDate  *time.Time `json:"last_record_date,omitempty"`
}

// RecordTypeDistribution represents distribution by record type
type RecordTypeDistribution struct {
	RecordType     string     `json:"record_type"`
	RecordCount    int64      `json:"record_count"`
	LastRecordDate *time.Time `json:"last_record_date,omitempty"`
}

// GrowthStatistics provides growth statistics for a dependent
type GrowthStatistics struct {
	MinWeight         *float64 `json:"min_weight,omitempty"`
	MaxWeight         *float64 `json:"max_weight,omitempty"`
	MinHeight         *float64 `json:"min_height,omitempty"`
	MaxHeight         *float64 `json:"max_height,omitempty"`
	MeasurementsCount int64    `json:"measurements_count"`
}
