package patients

import (
	"time"

	"github.com/google/uuid"
)

// ComprehensiveHealthRecord combines all patient health information
type ComprehensiveHealthRecord struct {
	Profile       PatientProfile         `json:"profile"`
	MedicalInfo   *PatientMedicalInfo    `json:"medical_info,omitempty"`
	Surgeries     []PatientSurgery       `json:"surgeries,omitempty"`
	Medications   []PatientMedication    `json:"medications,omitempty"`
	Immunizations []PatientImmunization  `json:"immunizations,omitempty"`
	FamilyHistory []PatientFamilyHistory `json:"family_history,omitempty"`
}

// EmergencyHealthInfo contains critical health information for emergency access
type EmergencyHealthInfo struct {
	PatientID            uuid.UUID             `json:"patient_id"`
	FirstName            string                `json:"first_name"`
	LastName             string                `json:"last_name"`
	DateOfBirth          *time.Time            `json:"date_of_birth,omitempty"`
	BloodType            *string               `json:"blood_type,omitempty"`
	DNRStatus            bool                  `json:"dnr_status"`
	OrganDonor           bool                  `json:"organ_donor"`
	PrimaryCarePhysician *string               `json:"primary_care_physician,omitempty"`
	ActiveMedications    []PatientMedication   `json:"active_medications"`
	RecentSurgeries      []PatientSurgery      `json:"recent_surgeries"`
	RecentImmunizations  []PatientImmunization `json:"recent_immunizations"`
}

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
