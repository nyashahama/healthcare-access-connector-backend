package providers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type clinicService struct {
	clinicRepo repository.ClinicRepository
	auditRepo  repository.AuditRepository
	userRepo   repository.UserRepository
	cache      cache.Service
	logger     *zerolog.Logger
}

func NewClinicService(
	clinicRepo repository.ClinicRepository,
	auditRepo repository.AuditRepository,
	userRepo repository.UserRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ClinicService {
	return &clinicService{
		clinicRepo: clinicRepo,
		auditRepo:  auditRepo,
		userRepo:   userRepo,
		cache:      cache,
		logger:     logger,
	}
}

func (c *clinicService) CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_name", clinic.ClinicName).
			Msg("CreateClinic completed")
	}()

	// Validate required fields
	if clinic.ClinicName == "" {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Clinic name is required", 400)
	}
	if clinic.ClinicType == "" {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Clinic type is required", 400)
	}
	if clinic.PhysicalAddress == "" {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Physical address is required", 400)
	}

	// Set timestamps and status
	now := time.Now()
	clinic.ID = uuid.New()
	clinic.IsVerified = false
	clinic.VerificationStatus = "pending"
	clinic.CreatedAt = now
	clinic.UpdatedAt = now

	// Create clinic
	createdClinic, err := c.clinicRepo.CreateClinic(ctx, clinic)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateRegistrationNumber) {
			return providers.Clinic{}, domain.NewAppError(err, "Registration number already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicateEmail) {
			return providers.Clinic{}, domain.NewAppError(err, "Email already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicatePhone) {
			return providers.Clinic{}, domain.NewAppError(err, "Phone number already exists", 409)
		}
		c.logger.Error().Err(err).Str("clinic_name", clinic.ClinicName).Msg("Failed to create clinic")
		return providers.Clinic{}, domain.NewAppError(err, "Failed to create clinic", 500)
	}

	// Invalidate cache for clinic listings
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_created", createdClinic.ID, nil, map[string]interface{}{
		"clinic_name": createdClinic.ClinicName,
		"clinic_type": createdClinic.ClinicType,
	})

	c.logger.Info().
		Str("clinic_id", createdClinic.ID.String()).
		Str("clinic_name", createdClinic.ClinicName).
		Str("clinic_type", createdClinic.ClinicType).
		Msg("Clinic created successfully")

	return createdClinic, nil
}

func (c *clinicService) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("GetClinicByID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:%s", id.String())
	var clinic providers.Clinic
	if err := c.cache.Get(ctx, cacheKey, &clinic); err == nil {
		c.logger.Debug().Str("clinic_id", id.String()).Msg("Clinic retrieved from cache")
		return clinic, nil
	}

	// Fetch from database
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return providers.Clinic{}, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic")
		return providers.Clinic{}, domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, clinic, 10*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinic")
	}

	return clinic, nil
}

func (c *clinicService) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinic.ID.String()).
			Msg("UpdateClinic completed")
	}()

	// Validate required fields
	if clinic.ClinicName == "" {
		return domain.NewAppError(domain.ErrValidation, "Clinic name is required", 400)
	}
	if clinic.ClinicType == "" {
		return domain.NewAppError(domain.ErrValidation, "Clinic type is required", 400)
	}

	// Get existing clinic to compare changes
	existing, err := c.clinicRepo.GetClinicByID(ctx, clinic.ID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Update timestamp
	clinic.UpdatedAt = time.Now()

	// Update clinic
	if err := c.clinicRepo.UpdateClinic(ctx, clinic); err != nil {
		c.logger.Error().Err(err).Str("clinic_id", clinic.ID.String()).Msg("Failed to update clinic")
		return domain.NewAppError(err, "Failed to update clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, clinic.ID)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_updated", clinic.ID, nil, map[string]interface{}{
		"clinic_name": clinic.ClinicName,
		"changes":     c.compareClinicChanges(existing, clinic),
	})

	c.logger.Info().
		Str("clinic_id", clinic.ID.String()).
		Str("clinic_name", clinic.ClinicName).
		Msg("Clinic updated successfully")

	return nil
}

func (c *clinicService) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("DeleteClinic completed")
	}()

	// Get clinic first for audit logging
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrClinicNotFound) {
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic for deletion")
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Delete clinic
	if err := c.clinicRepo.DeleteClinic(ctx, id); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to delete clinic")
		return domain.NewAppError(err, "Failed to delete clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	if clinic.ID != uuid.Nil {
		c.logClinicActivity(ctx, "clinic_deleted", id, nil, map[string]interface{}{
			"clinic_name": clinic.ClinicName,
		})
	}

	c.logger.Info().
		Str("clinic_id", id.String()).
		Msg("Clinic deleted successfully")

	return nil
}

func (c *clinicService) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Str("verified_by", verifiedBy.String()).
			Msg("VerifyClinic completed")
	}()

	// Verify the verifier exists
	if _, err := c.userRepo.GetUserByID(ctx, verifiedBy); err != nil {
		return domain.NewAppError(domain.ErrUserNotFound, "Verifier not found", 404)
	}

	// Verify clinic
	if err := c.clinicRepo.VerifyClinic(ctx, id, verifiedBy, notes); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to verify clinic")
		return domain.NewAppError(err, "Failed to verify clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_verified", id, &verifiedBy, map[string]interface{}{
		"verification_notes": notes,
	})

	c.logger.Info().
		Str("clinic_id", id.String()).
		Str("verified_by", verifiedBy.String()).
		Msg("Clinic verified successfully")

	return nil
}

func (c *clinicService) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Str("verified_by", verifiedBy.String()).
			Msg("RejectClinicVerification completed")
	}()

	// Verify the verifier exists
	if _, err := c.userRepo.GetUserByID(ctx, verifiedBy); err != nil {
		return domain.NewAppError(domain.ErrUserNotFound, "Verifier not found", 404)
	}

	// Reject clinic verification
	if err := c.clinicRepo.RejectClinicVerification(ctx, id, verifiedBy, notes); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to reject clinic verification")
		return domain.NewAppError(err, "Failed to reject clinic verification", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_verification_rejected", id, &verifiedBy, map[string]interface{}{
		"rejection_notes": notes,
	})

	c.logger.Info().
		Str("clinic_id", id.String()).
		Str("verified_by", verifiedBy.String()).
		Msg("Clinic verification rejected")

	return nil
}

func (c *clinicService) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Str("status", status).
			Msg("UpdateClinicVerificationStatus completed")
	}()

	// Validate status
	validStatuses := map[string]bool{
		"pending":    true,
		"verified":   true,
		"rejected":   true,
		"in_review":  true,
		"unverified": true,
	}
	if !validStatuses[status] {
		return domain.NewAppError(domain.ErrValidation, "Invalid verification status", 400)
	}

	// Update verification status
	if err := c.clinicRepo.UpdateClinicVerificationStatus(ctx, id, status); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to update clinic verification status")
		return domain.NewAppError(err, "Failed to update verification status", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_verification_status_updated", id, nil, map[string]interface{}{
		"status": status,
	})

	c.logger.Info().
		Str("clinic_id", id.String()).
		Str("status", status).
		Msg("Clinic verification status updated")

	return nil
}

func (c *clinicService) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("DeactivateClinic completed")
	}()

	// Get clinic for audit logging
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrClinicNotFound) {
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic for deactivation")
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Deactivate clinic
	if err := c.clinicRepo.DeactivateClinic(ctx, id); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to deactivate clinic")
		return domain.NewAppError(err, "Failed to deactivate clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	if clinic.ID != uuid.Nil {
		c.logClinicActivity(ctx, "clinic_deactivated", id, nil, map[string]interface{}{
			"clinic_name": clinic.ClinicName,
		})
	}

	c.logger.Info().
		Str("clinic_id", id.String()).
		Msg("Clinic deactivated")

	return nil
}

func (c *clinicService) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("ReactivateClinic completed")
	}()

	// Get clinic for audit logging
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrClinicNotFound) {
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic for reactivation")
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Reactivate clinic
	if err := c.clinicRepo.ReactivateClinic(ctx, id); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to reactivate clinic")
		return domain.NewAppError(err, "Failed to reactivate clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	if clinic.ID != uuid.Nil {
		c.logClinicActivity(ctx, "clinic_reactivated", id, nil, map[string]interface{}{
			"clinic_name": clinic.ClinicName,
		})
	}

	c.logger.Info().
		Str("clinic_id", id.String()).
		Msg("Clinic reactivated")

	return nil
}

func (c *clinicService) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("query", params.Query).
			Int("limit", params.Limit).
			Int("offset", params.Offset).
			Msg("SearchClinics completed")
	}()

	// Validate limit and offset
	if params.Limit <= 0 || params.Limit > 100 {
		params.Limit = 50
	}
	if params.Offset < 0 {
		params.Offset = 0
	}

	// Try cache first (for common search patterns)
	cacheKey := fmt.Sprintf("clinic:search:%s:%s:%s:%d:%d",
		params.Query,
		stringPtrToString(params.Province),
		stringPtrToString(params.City),
		params.Limit,
		params.Offset,
	)
	var results []providers.ClinicSearchResult
	if err := c.cache.Get(ctx, cacheKey, &results); err == nil {
		c.logger.Debug().Str("query", params.Query).Msg("Search results retrieved from cache")
		return results, nil
	}

	// Search clinics
	results, err := c.clinicRepo.SearchClinics(ctx, params)
	if err != nil {
		c.logger.Error().Err(err).Str("query", params.Query).Msg("Failed to search clinics")
		return nil, domain.NewAppError(err, "Failed to search clinics", 500)
	}

	// Cache the result (shorter TTL for search results)
	if err := c.cache.Set(ctx, cacheKey, results, 2*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache search results")
	}

	c.logger.Debug().
		Str("query", params.Query).
		Int("result_count", len(results)).
		Msg("Clinics search completed")

	return results, nil
}

func (c *clinicService) GetClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Int("limit", limit).
			Int("offset", offset).
			Msg("GetClinics completed")
	}()

	// Validate limit and offset
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:list:%s:%s:%s:%s:%d:%d",
		stringPtrToString(filters.ClinicType),
		stringPtrToString(filters.Province),
		stringPtrToString(filters.City),
		stringPtrToString(filters.VerificationStatus),
		limit,
		offset,
	)
	var clinics []providers.Clinic
	if err := c.cache.Get(ctx, cacheKey, &clinics); err == nil {
		c.logger.Debug().Msg("Clinics list retrieved from cache")
		return clinics, nil
	}

	// Get clinics
	clinics, err := c.clinicRepo.GetClinics(ctx, filters, limit, offset)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to get clinics")
		return nil, domain.NewAppError(err, "Failed to get clinics", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, clinics, 5*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinics list")
	}

	c.logger.Debug().
		Int("clinic_count", len(clinics)).
		Msg("Clinics list retrieved")

	return clinics, nil
}

// Helper methods
func (c *clinicService) invalidateClinicCache(ctx context.Context, clinicID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("clinic:%s", clinicID.String()),
	}
	for _, key := range cacheKeys {
		if err := c.cache.Delete(ctx, key); err != nil {
			c.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate clinic cache")
		}
	}
}

func (c *clinicService) invalidateClinicListCache(ctx context.Context) {
	// Invalidate all clinic listing caches (pattern matching would be needed)
	// For now, we'll clear common patterns
	patterns := []string{
		"clinic:list:*",
		"clinic:search:*",
	}
	for _, pattern := range patterns {
		// Note: This requires cache implementation with pattern matching support
		c.logger.Debug().Str("pattern", pattern).Msg("Would invalidate cache pattern")
	}
}

func (c *clinicService) logClinicActivity(ctx context.Context, activityType string, clinicID uuid.UUID, userID *uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("clinic"),
		ResourceID:      &clinicID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			c.logger.Warn().Err(err).Msg("Failed to log clinic activity")
		}
	}()
}

func (c *clinicService) compareClinicChanges(oldClinic, newClinic providers.Clinic) map[string]interface{} {
	changes := make(map[string]interface{})

	if oldClinic.ClinicName != newClinic.ClinicName {
		changes["clinic_name"] = map[string]string{
			"old": oldClinic.ClinicName,
			"new": newClinic.ClinicName,
		}
	}
	if oldClinic.ClinicType != newClinic.ClinicType {
		changes["clinic_type"] = map[string]string{
			"old": oldClinic.ClinicType,
			"new": newClinic.ClinicType,
		}
	}
	// Add more field comparisons as needed

	return changes
}

func stringPtrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func stringPtr(s string) *string {
	return &s
}
