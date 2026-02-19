package telemedicine

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
)

// ─── Request DTOs ──────────────────────────────────────────────────────────────

// UpsertAvailabilityRequest is the provider-facing payload for going online and
// setting initial availability preferences for a shift.
type UpsertAvailabilityRequest struct {
	IsOnline                   bool                                    `json:"is_online"`
	IsAccepting                bool                                    `json:"is_accepting"`
	Status                     telemedicine.ProviderAvailabilityStatus `json:"status"`
	MaxConcurrentConsultations int                                     `json:"max_concurrent_consultations"`
	EstimatedWaitMinutes       *int                                    `json:"estimated_wait_minutes,omitempty"`
	StatusMessage              *string                                 `json:"status_message,omitempty"`
	ConsultationFeeOverride    *float64                                `json:"consultation_fee_override,omitempty"`
}

// UpdateAvailabilityStatusRequest is the lightweight payload used for mid-shift
// status changes (e.g. available → busy → away).
type UpdateAvailabilityStatusRequest struct {
	Status               telemedicine.ProviderAvailabilityStatus `json:"status"`
	IsAccepting          bool                                    `json:"is_accepting"`
	EstimatedWaitMinutes *int                                    `json:"estimated_wait_minutes,omitempty"`
	StatusMessage        *string                                 `json:"status_message,omitempty"`
}

// HeartbeatRequest is sent periodically by the provider client to keep the
// last_seen_at timestamp fresh and prevent the stale-provider job from marking
// them offline.
type HeartbeatRequest struct {
	StaffID uuid.UUID `json:"staff_id"`
}

// GoOfflineRequest is the provider-facing payload for explicitly ending a shift.
type GoOfflineRequest struct {
	StaffID uuid.UUID `json:"staff_id"`
}

// GetAvailableProvidersBySpecializationRequest filters the provider list by
// clinical specialization.
type GetAvailableProvidersBySpecializationRequest struct {
	Specialization string `json:"specialization"`
}

// ─── Response DTOs ─────────────────────────────────────────────────────────────

// ProviderAvailabilityResponse is the full availability record returned after
// upsert or individual GET. Used in provider-facing admin/self-service views.
type ProviderAvailabilityResponse struct {
	ID                         uuid.UUID                               `json:"id"`
	StaffID                    uuid.UUID                               `json:"staff_id"`
	IsOnline                   bool                                    `json:"is_online"`
	IsAccepting                bool                                    `json:"is_accepting"`
	Status                     telemedicine.ProviderAvailabilityStatus `json:"status"`
	ActiveConsultationCount    int                                     `json:"active_consultation_count"`
	MaxConcurrentConsultations int                                     `json:"max_concurrent_consultations"`
	EstimatedWaitMinutes       *int                                    `json:"estimated_wait_minutes,omitempty"`
	StatusMessage              *string                                 `json:"status_message,omitempty"`
	ConsultationFeeOverride    *float64                                `json:"consultation_fee_override,omitempty"`
	LastSeenAt                 *time.Time                              `json:"last_seen_at,omitempty"`
	ShiftStart                 *time.Time                              `json:"shift_start,omitempty"`
	UpdatedAt                  time.Time                               `json:"updated_at"`
}

// AvailableProviderResponse is the patient-facing projection powering the
// provider list. It joins availability with staff profile fields.
type AvailableProviderResponse struct {
	StaffID                    uuid.UUID                               `json:"staff_id"`
	Status                     telemedicine.ProviderAvailabilityStatus `json:"status"`
	EstimatedWaitMinutes       *int                                    `json:"estimated_wait_minutes,omitempty"`
	ActiveConsultationCount    int                                     `json:"active_consultation_count"`
	MaxConcurrentConsultations int                                     `json:"max_concurrent_consultations"`
	ConsultationFeeOverride    *float64                                `json:"consultation_fee_override,omitempty"`
	StatusMessage              *string                                 `json:"status_message,omitempty"`
	Title                      *string                                 `json:"title,omitempty"`
	FirstName                  string                                  `json:"first_name"`
	LastName                   string                                  `json:"last_name"`
	ProfessionalTitle          *string                                 `json:"professional_title,omitempty"`
	Specialization             *string                                 `json:"specialization,omitempty"`
	Bio                        *string                                 `json:"bio,omitempty"`
	ProfilePictureURL          *string                                 `json:"profile_picture_url,omitempty"`
	YearsExperience            *int                                    `json:"years_experience,omitempty"`
	LanguagesSpoken            []string                                `json:"languages_spoken,omitempty"`
}

// AvailableProviderBySpecializationResponse is the slimmer projection used in
// the specialization-filtered provider list.
type AvailableProviderBySpecializationResponse struct {
	StaffID                 uuid.UUID                               `json:"staff_id"`
	Status                  telemedicine.ProviderAvailabilityStatus `json:"status"`
	EstimatedWaitMinutes    *int                                    `json:"estimated_wait_minutes,omitempty"`
	ConsultationFeeOverride *float64                                `json:"consultation_fee_override,omitempty"`
	FirstName               string                                  `json:"first_name"`
	LastName                string                                  `json:"last_name"`
	ProfessionalTitle       *string                                 `json:"professional_title,omitempty"`
	Specialization          *string                                 `json:"specialization,omitempty"`
	ProfilePictureURL       *string                                 `json:"profile_picture_url,omitempty"`
	YearsExperience         *int                                    `json:"years_experience,omitempty"`
}

// ─── List wrappers ─────────────────────────────────────────────────────────────

// AvailableProvidersResponse wraps the full provider list.
type AvailableProvidersResponse struct {
	Providers []AvailableProviderResponse `json:"providers"`
	Count     int                         `json:"count"`
}

// AvailableProvidersBySpecializationResponse wraps the filtered provider list.
type AvailableProvidersBySpecializationResponse struct {
	Providers []AvailableProviderBySpecializationResponse `json:"providers"`
	Count     int                                         `json:"count"`
}

// ─── Conversion helpers ────────────────────────────────────────────────────────

// ToProviderAvailabilityResponse converts a domain ProviderAvailability to its
// response DTO.
func ToProviderAvailabilityResponse(a telemedicine.ProviderAvailability) ProviderAvailabilityResponse {
	return ProviderAvailabilityResponse{
		ID:                         a.ID,
		StaffID:                    a.StaffID,
		IsOnline:                   a.IsOnline,
		IsAccepting:                a.IsAccepting,
		Status:                     a.Status,
		ActiveConsultationCount:    a.ActiveConsultationCount,
		MaxConcurrentConsultations: a.MaxConcurrentConsultations,
		EstimatedWaitMinutes:       a.EstimatedWaitMinutes,
		StatusMessage:              a.StatusMessage,
		ConsultationFeeOverride:    a.ConsultationFeeOverride,
		LastSeenAt:                 a.LastSeenAt,
		ShiftStart:                 a.ShiftStart,
		UpdatedAt:                  a.UpdatedAt,
	}
}

// ToAvailableProviderResponse converts the patient-facing hydrated domain projection.
func ToAvailableProviderResponse(p telemedicine.AvailableProvider) AvailableProviderResponse {
	return AvailableProviderResponse{
		StaffID:                    p.StaffID,
		Status:                     p.Status,
		EstimatedWaitMinutes:       p.EstimatedWaitMinutes,
		ActiveConsultationCount:    p.ActiveConsultationCount,
		MaxConcurrentConsultations: p.MaxConcurrentConsultations,
		ConsultationFeeOverride:    p.ConsultationFeeOverride,
		StatusMessage:              p.StatusMessage,
		Title:                      p.Title,
		FirstName:                  p.FirstName,
		LastName:                   p.LastName,
		ProfessionalTitle:          p.ProfessionalTitle,
		Specialization:             p.Specialization,
		Bio:                        p.Bio,
		ProfilePictureURL:          p.ProfilePictureURL,
		YearsExperience:            p.YearsExperience,
		LanguagesSpoken:            p.LanguagesSpoken,
	}
}

// ToAvailableProviderBySpecializationResponse converts the slim specialization
// filtered projection.
func ToAvailableProviderBySpecializationResponse(p telemedicine.AvailableProviderBySpecialization) AvailableProviderBySpecializationResponse {
	return AvailableProviderBySpecializationResponse{
		StaffID:                 p.StaffID,
		Status:                  p.Status,
		EstimatedWaitMinutes:    p.EstimatedWaitMinutes,
		ConsultationFeeOverride: p.ConsultationFeeOverride,
		FirstName:               p.FirstName,
		LastName:                p.LastName,
		ProfessionalTitle:       p.ProfessionalTitle,
		Specialization:          p.Specialization,
		ProfilePictureURL:       p.ProfilePictureURL,
		YearsExperience:         p.YearsExperience,
	}
}

// ToDomainAvailability converts an UpsertAvailabilityRequest to the domain model.
func ToDomainAvailability(staffID uuid.UUID, req UpsertAvailabilityRequest) telemedicine.ProviderAvailability {
	return telemedicine.ProviderAvailability{
		StaffID:                    staffID,
		IsOnline:                   req.IsOnline,
		IsAccepting:                req.IsAccepting,
		Status:                     req.Status,
		MaxConcurrentConsultations: req.MaxConcurrentConsultations,
		EstimatedWaitMinutes:       req.EstimatedWaitMinutes,
		StatusMessage:              req.StatusMessage,
		ConsultationFeeOverride:    req.ConsultationFeeOverride,
	}
}
