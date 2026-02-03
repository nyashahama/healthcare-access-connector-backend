package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// DTOs for Service

type CreateServiceRequest struct {
	ClinicID                uuid.UUID      `json:"clinic_id" binding:"required"`
	ServiceName             string         `json:"service_name" binding:"required,min=1"`
	ServiceCategory         *string        `json:"service_category,omitempty"`
	Description             *string        `json:"description,omitempty"`
	DurationMinutes         *int           `json:"duration_minutes,omitempty" binding:"min=1"`
	PreparationInstructions *string        `json:"preparation_instructions,omitempty"`
	FollowUpRequired        bool           `json:"follow_up_required"`
	FollowUpDays            *int           `json:"follow_up_days,omitempty" binding:"min=1"`
	MinimumAge              *int           `json:"minimum_age,omitempty" binding:"min=0,max=150"`
	MaximumAge              *int           `json:"maximum_age,omitempty" binding:"min=0,max=150"`
	GenderRestriction       *string        `json:"gender_restriction,omitempty" binding:"oneof=male female none"`
	Prerequisites           []string       `json:"prerequisites,omitempty"`
	Cost                    *float64       `json:"cost,omitempty" binding:"min=0"`
	CostCurrency            string         `json:"cost_currency" binding:"len=3"`
	IsCoveredByMedicalAid   bool           `json:"is_covered_by_medical_aid"`
	MedicalAidCodes         map[string]any `json:"medical_aid_codes,omitempty"`
	IsActive                bool           `json:"is_active"`
	AvailableDays           []string       `json:"available_days,omitempty"`
	RequiresAppointment     bool           `json:"requires_appointment"`
	WalkInAllowed           bool           `json:"walk_in_allowed"`
	ProvidedByStaffIDs      []uuid.UUID    `json:"provided_by_staff_ids,omitempty"`
}

type UpdateServiceRequest struct {
	ServiceName             string         `json:"service_name" binding:"required,min=1"`
	ServiceCategory         *string        `json:"service_category,omitempty"`
	Description             *string        `json:"description,omitempty"`
	DurationMinutes         *int           `json:"duration_minutes,omitempty" binding:"min=1"`
	PreparationInstructions *string        `json:"preparation_instructions,omitempty"`
	FollowUpRequired        bool           `json:"follow_up_required"`
	FollowUpDays            *int           `json:"follow_up_days,omitempty" binding:"min=1"`
	MinimumAge              *int           `json:"minimum_age,omitempty" binding:"min=0,max=150"`
	MaximumAge              *int           `json:"maximum_age,omitempty" binding:"min=0,max=150"`
	GenderRestriction       *string        `json:"gender_restriction,omitempty" binding:"oneof=male female none"`
	Prerequisites           []string       `json:"prerequisites,omitempty"`
	Cost                    *float64       `json:"cost,omitempty" binding:"min=0"`
	CostCurrency            string         `json:"cost_currency" binding:"len=3"`
	IsCoveredByMedicalAid   bool           `json:"is_covered_by_medical_aid"`
	MedicalAidCodes         map[string]any `json:"medical_aid_codes,omitempty"`
	IsActive                bool           `json:"is_active"`
	AvailableDays           []string       `json:"available_days,omitempty"`
	RequiresAppointment     bool           `json:"requires_appointment"`
	WalkInAllowed           bool           `json:"walk_in_allowed"`
	ProvidedByStaffIDs      []uuid.UUID    `json:"provided_by_staff_ids,omitempty"`
}

type ServiceResponse struct {
	ID                      uuid.UUID      `json:"id"`
	ClinicID                uuid.UUID      `json:"clinic_id"`
	ServiceName             string         `json:"service_name"`
	ServiceCategory         *string        `json:"service_category,omitempty"`
	Description             *string        `json:"description,omitempty"`
	DurationMinutes         *int           `json:"duration_minutes,omitempty"`
	PreparationInstructions *string        `json:"preparation_instructions,omitempty"`
	FollowUpRequired        bool           `json:"follow_up_required"`
	FollowUpDays            *int           `json:"follow_up_days,omitempty"`
	MinimumAge              *int           `json:"minimum_age,omitempty"`
	MaximumAge              *int           `json:"maximum_age,omitempty"`
	GenderRestriction       *string        `json:"gender_restriction,omitempty"`
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

type ServiceListResponse struct {
	Services []ServiceResponse `json:"services"`
	Total    int               `json:"total"`
}

// Helper function to convert domain to response
func serviceToResponse(svc providers.ClinicService) ServiceResponse {
	return ServiceResponse{
		ID:                      svc.ID,
		ClinicID:                svc.ClinicID,
		ServiceName:             svc.ServiceName,
		ServiceCategory:         svc.ServiceCategory,
		Description:             svc.Description,
		DurationMinutes:         svc.DurationMinutes,
		PreparationInstructions: svc.PreparationInstructions,
		FollowUpRequired:        svc.FollowUpRequired,
		FollowUpDays:            svc.FollowUpDays,
		MinimumAge:              svc.MinimumAge,
		MaximumAge:              svc.MaximumAge,
		GenderRestriction:       svc.GenderRestriction,
		Prerequisites:           svc.Prerequisites,
		Cost:                    svc.Cost,
		CostCurrency:            svc.CostCurrency,
		IsCoveredByMedicalAid:   svc.IsCoveredByMedicalAid,
		MedicalAidCodes:         svc.MedicalAidCodes,
		IsActive:                svc.IsActive,
		AvailableDays:           svc.AvailableDays,
		RequiresAppointment:     svc.RequiresAppointment,
		WalkInAllowed:           svc.WalkInAllowed,
		ProvidedByStaffIDs:      svc.ProvidedByStaffIDs,
		PopularityScore:         svc.PopularityScore,
		AverageRating:           svc.AverageRating,
		ReviewCount:             svc.ReviewCount,
		CreatedAt:               svc.CreatedAt,
		UpdatedAt:               svc.UpdatedAt,
	}
}
