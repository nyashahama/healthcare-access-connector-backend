package telemedicine

import (
	"time"

	"github.com/google/uuid"
)

// ProviderAvailabilityStatus represents the real-time status visible to patients.
type ProviderAvailabilityStatus string

const (
	AvailabilityStatusAvailable ProviderAvailabilityStatus = "available"
	AvailabilityStatusBusy      ProviderAvailabilityStatus = "busy"
	AvailabilityStatusAway      ProviderAvailabilityStatus = "away"
	AvailabilityStatusOffline   ProviderAvailabilityStatus = "offline"
)

// ProviderAvailability is the core domain model for a provider's live presence.
// A row is upserted on first login and kept alive via heartbeat pings.
type ProviderAvailability struct {
	ID      uuid.UUID `json:"id"`
	StaffID uuid.UUID `json:"staff_id"`

	// Online / accepting state
	IsOnline    bool                       `json:"is_online"`
	IsAccepting bool                       `json:"is_accepting"`
	Status      ProviderAvailabilityStatus `json:"status"`

	// Concurrency control
	ActiveConsultationCount    int `json:"active_consultation_count"`
	MaxConcurrentConsultations int `json:"max_concurrent_consultations"`

	// Patient-facing display
	EstimatedWaitMinutes *int    `json:"estimated_wait_minutes,omitempty"`
	StatusMessage        *string `json:"status_message,omitempty"`

	// Fee override for this provider session (overrides the clinic default)
	ConsultationFeeOverride *float64 `json:"consultation_fee_override,omitempty"`

	// Heartbeat / shift tracking
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	ShiftStart *time.Time `json:"shift_start,omitempty"`

	UpdatedAt time.Time `json:"updated_at"`
}

// AvailableProvider is the patient-facing projection powering the provider list.
// It joins provider_availability with clinic_staff profile fields.
type AvailableProvider struct {
	StaffID                    uuid.UUID                  `json:"staff_id"`
	Status                     ProviderAvailabilityStatus `json:"status"`
	EstimatedWaitMinutes       *int                       `json:"estimated_wait_minutes,omitempty"`
	ActiveConsultationCount    int                        `json:"active_consultation_count"`
	MaxConcurrentConsultations int                        `json:"max_concurrent_consultations"`
	ConsultationFeeOverride    *float64                   `json:"consultation_fee_override,omitempty"`
	StatusMessage              *string                    `json:"status_message,omitempty"`

	// Staff profile fields (from clinic_staff)
	Title            *string  `json:"title,omitempty"`
	FirstName        string   `json:"first_name"`
	LastName         string   `json:"last_name"`
	ProfessionalTitle *string `json:"professional_title,omitempty"`
	Specialization   *string  `json:"specialization,omitempty"`
	Bio              *string  `json:"bio,omitempty"`
	ProfilePictureURL *string `json:"profile_picture_url,omitempty"`
	YearsExperience  *int     `json:"years_experience,omitempty"`
	LanguagesSpoken  []string `json:"languages_spoken,omitempty"`
}

// AvailableProviderBySpecialization is the slimmer projection used in the
// specialization-filtered provider list query.
type AvailableProviderBySpecialization struct {
	StaffID                 uuid.UUID                  `json:"staff_id"`
	Status                  ProviderAvailabilityStatus `json:"status"`
	EstimatedWaitMinutes    *int                       `json:"estimated_wait_minutes,omitempty"`
	ConsultationFeeOverride *float64                   `json:"consultation_fee_override,omitempty"`
	FirstName               string                     `json:"first_name"`
	LastName                string                     `json:"last_name"`
	ProfessionalTitle       *string                    `json:"professional_title,omitempty"`
	Specialization          *string                    `json:"specialization,omitempty"`
	ProfilePictureURL       *string                    `json:"profile_picture_url,omitempty"`
	YearsExperience         *int                       `json:"years_experience,omitempty"`
}

// StaleProvider is the minimal projection returned by the background-job stale
// provider query — only the staff_id is needed to drive the offline update.
type StaleProvider struct {
	StaffID uuid.UUID `json:"staff_id"`
}