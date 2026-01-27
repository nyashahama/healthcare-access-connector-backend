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

// ============================================
// SUPPORTING TYPES - SERVICE REPOSITORY
// ============================================

type ServiceDetails struct {
	Description             *string
	DurationMinutes         *int
	PreparationInstructions *string
	FollowUpRequired        bool
	FollowUpDays            *int
}

type ServiceEligibility struct {
	MinimumAge        *int
	MaximumAge        *int
	GenderRestriction *string
	Prerequisites     []string
}

type ServiceCost struct {
	Cost                  *float64
	CostCurrency          string
	IsCoveredByMedicalAid bool
	MedicalAidCodes       map[string]any
}

type ServiceAvailability struct {
	AvailableDays       []string
	RequiresAppointment bool
	WalkInAllowed       bool
}

type ServiceStatistics struct {
	ID              uuid.UUID
	ServiceName     string
	AverageRating   *float64
	ReviewCount     int
	PopularityScore int
	Cost            *float64
	CreatedAt       time.Time
}

type ServiceMetrics struct {
	TotalServices      int64
	ActiveServices     int64
	InactiveServices   int64
	AverageCost        *float64
	AverageDuration    *float64
	OverallRating      *float64
	TotalReviews       int64
	MedicalAidServices int64
	WalkInServices     int64
}

type ServiceCategoryDistribution struct {
	ServiceCategory string
	Count           int64
	AverageCost     *float64
	AverageRating   *float64
}

type ServicePriceDistribution struct {
	PriceRange    string
	Count         int64
	AverageRating *float64
}

type ServiceComparison struct {
	ClinicID              uuid.UUID
	ClinicName            string
	Cost                  *float64
	DurationMinutes       *int
	AverageRating         *float64
	IsCoveredByMedicalAid bool
}

type ServiceProvider struct {
	ClinicID    uuid.UUID
	ClinicName  string
	ServiceName string
	Cost        *float64
	City        *string
	Province    *string
}
