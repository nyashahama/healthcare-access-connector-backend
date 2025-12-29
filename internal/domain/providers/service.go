package providers

import (
	"time"

	"github.com/google/uuid"
)

// ClinicService represents a service offered by a clinic
type ClinicService struct {
	ID                      uuid.UUID      `json:"id"`
	ClinicID                uuid.UUID      `json:"clinic_id"`
	ServiceName             string         `json:"service_name"`
	ServiceCategory         *string        `json:"service_category,omitempty"` // preventive, pediatric, adult, testing, women_health
	Description             *string        `json:"description,omitempty"`
	DurationMinutes         *int           `json:"duration_minutes,omitempty"`
	PreparationInstructions *string        `json:"preparation_instructions,omitempty"`
	FollowUpRequired        bool           `json:"follow_up_required"`
	FollowUpDays            *int           `json:"follow_up_days,omitempty"`
	MinimumAge              *int           `json:"minimum_age,omitempty"`
	MaximumAge              *int           `json:"maximum_age,omitempty"`
	GenderRestriction       *string        `json:"gender_restriction,omitempty"` // male, female, none
	Prerequisites           []string       `json:"prerequisites,omitempty"`
	Cost                    *float64       `json:"cost,omitempty"`
	CostCurrency            string         `json:"cost_currency"`
	IsCoveredByMedicalAid   bool           `json:"is_covered_by_medical_aid"`
	MedicalAidCodes         map[string]any `json:"medical_aid_codes,omitempty"`
	IsActive                bool           `json:"is_active"`
	AvailableDays           []string       `json:"available_days,omitempty"`
	RequiresAppointment     bool           `json:"requires_appointment"`
	WalkInAllowed           bool           `json:"walk_in_allowed"`
	ProvidedByStaffIDs      []uuid.UUID    `json:"provided_by_staff_ids,omitempty"`
	PopularityScore         int            `json:"popularity_score"`
	AverageRating           *float64       `json:"average_rating,omitempty"`
	ReviewCount             int            `json:"review_count"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
}