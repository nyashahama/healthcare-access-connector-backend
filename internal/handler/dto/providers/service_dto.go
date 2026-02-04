package providers

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// CreateServiceRequest represents a request to create a service
type CreateServiceRequest struct {
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
}

// UpdateServiceRequest represents a request to update a service
type UpdateServiceRequest struct {
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
}

// ServiceResponse represents a service in responses
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

// ServiceListResponse represents a list of services
type ServiceListResponse struct {
	Services []ServiceResponse `json:"services"`
	Total    int               `json:"total"`
	Limit    int               `json:"limit,omitempty"`
	Offset   int               `json:"offset,omitempty"`
}

// ToServiceResponse converts domain ClinicService to response DTO
func ToServiceResponse(service providers.ClinicService) ServiceResponse {
	return ServiceResponse{
		ID:                      service.ID,
		ClinicID:                service.ClinicID,
		ServiceName:             service.ServiceName,
		ServiceCategory:         service.ServiceCategory,
		Description:             service.Description,
		DurationMinutes:         service.DurationMinutes,
		PreparationInstructions: service.PreparationInstructions,
		FollowUpRequired:        service.FollowUpRequired,
		FollowUpDays:            service.FollowUpDays,
		MinimumAge:              service.MinimumAge,
		MaximumAge:              service.MaximumAge,
		GenderRestriction:       service.GenderRestriction,
		Prerequisites:           service.Prerequisites,
		Cost:                    service.Cost,
		CostCurrency:            service.CostCurrency,
		IsCoveredByMedicalAid:   service.IsCoveredByMedicalAid,
		MedicalAidCodes:         service.MedicalAidCodes,
		IsActive:                service.IsActive,
		AvailableDays:           service.AvailableDays,
		RequiresAppointment:     service.RequiresAppointment,
		WalkInAllowed:           service.WalkInAllowed,
		ProvidedByStaffIDs:      service.ProvidedByStaffIDs,
		PopularityScore:         service.PopularityScore,
		AverageRating:           service.AverageRating,
		ReviewCount:             service.ReviewCount,
		CreatedAt:               service.CreatedAt,
		UpdatedAt:               service.UpdatedAt,
	}
}

// ToDomainService converts request DTO to domain model
func ToDomainService(req CreateServiceRequest) providers.ClinicService {
	return providers.ClinicService{
		ClinicID:                req.ClinicID,
		ServiceName:             req.ServiceName,
		ServiceCategory:         req.ServiceCategory,
		Description:             req.Description,
		DurationMinutes:         req.DurationMinutes,
		PreparationInstructions: req.PreparationInstructions,
		FollowUpRequired:        req.FollowUpRequired,
		FollowUpDays:            req.FollowUpDays,
		MinimumAge:              req.MinimumAge,
		MaximumAge:              req.MaximumAge,
		GenderRestriction:       req.GenderRestriction,
		Prerequisites:           req.Prerequisites,
		Cost:                    req.Cost,
		CostCurrency:            req.CostCurrency,
		IsCoveredByMedicalAid:   req.IsCoveredByMedicalAid,
		MedicalAidCodes:         req.MedicalAidCodes,
		IsActive:                req.IsActive,
		AvailableDays:           req.AvailableDays,
		RequiresAppointment:     req.RequiresAppointment,
		WalkInAllowed:           req.WalkInAllowed,
		ProvidedByStaffIDs:      req.ProvidedByStaffIDs,
	}
}

// UpdateToDomainService updates existing domain model with request data
func UpdateToDomainService(existing providers.ClinicService, req UpdateServiceRequest) providers.ClinicService {
	existing.ServiceName = req.ServiceName
	existing.ServiceCategory = req.ServiceCategory
	existing.Description = req.Description
	existing.DurationMinutes = req.DurationMinutes
	existing.PreparationInstructions = req.PreparationInstructions
	existing.FollowUpRequired = req.FollowUpRequired
	existing.FollowUpDays = req.FollowUpDays
	existing.MinimumAge = req.MinimumAge
	existing.MaximumAge = req.MaximumAge
	existing.GenderRestriction = req.GenderRestriction
	if len(req.Prerequisites) > 0 {
		existing.Prerequisites = req.Prerequisites
	}
	existing.Cost = req.Cost
	existing.CostCurrency = req.CostCurrency
	existing.IsCoveredByMedicalAid = req.IsCoveredByMedicalAid
	existing.MedicalAidCodes = req.MedicalAidCodes
	existing.IsActive = req.IsActive
	if len(req.AvailableDays) > 0 {
		existing.AvailableDays = req.AvailableDays
	}
	existing.RequiresAppointment = req.RequiresAppointment
	existing.WalkInAllowed = req.WalkInAllowed
	if len(req.ProvidedByStaffIDs) > 0 {
		existing.ProvidedByStaffIDs = req.ProvidedByStaffIDs
	}
	return existing
}
