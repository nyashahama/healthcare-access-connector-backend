package patients

import "github.com/google/uuid"

// DependentWithRecords combines dependent info with health records
type DependentWithRecords struct {
	Dependent     PatientDependent        `json:"dependent"`
	HealthRecords []DependentHealthRecord `json:"health_records"`
	Statistics    HealthRecordStatistics  `json:"statistics"`
}

// PatientWithDependents represents a patient with their dependents
type PatientWithDependents struct {
	PatientID  uuid.UUID          `json:"patient_id"`
	FirstName  string             `json:"first_name"`
	LastName   string             `json:"last_name"`
	Dependents []PatientDependent `json:"dependents"`
}

// HighRiskPatient represents patients with severe conditions
type HighRiskPatient struct {
	PatientID            uuid.UUID `json:"patient_id"`
	FirstName            string    `json:"first_name"`
	LastName             string    `json:"last_name"`
	SevereConditionCount int64     `json:"severe_condition_count"`
	Conditions           string    `json:"conditions"`
}

// PatientAllergyProfile represents a patient's complete allergy profile
type PatientAllergyProfile struct {
	PatientID        uuid.UUID               `json:"patient_id"`
	FirstName        string                  `json:"first_name"`
	LastName         string                  `json:"last_name"`
	Allergies        []PatientAllergy        `json:"allergies"`
	CriticalWarnings CriticalAllergyWarnings `json:"critical_warnings"`
}

// PatientSafetyProfile combines allergies, conditions, and emergency contacts
type PatientSafetyProfile struct {
	PatientID         uuid.UUID          `json:"patient_id"`
	FirstName         string             `json:"first_name"`
	LastName          string             `json:"last_name"`
	Allergies         []PatientAllergy   `json:"allergies"`
	Conditions        []PatientCondition `json:"conditions"`
	EmergencyContacts []EmergencyContact `json:"emergency_contacts"`
}
