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

type staffService struct {
	staffRepo  repository.StaffRepository
	clinicRepo repository.ClinicRepository
	userRepo   repository.UserRepository
	auditRepo  repository.AuditRepository
	cache      cache.Service
	logger     *zerolog.Logger
}

func NewStaffService(
	staffRepo repository.StaffRepository,
	clinicRepo repository.ClinicRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.StaffService {
	return &staffService{
		staffRepo:  staffRepo,
		clinicRepo: clinicRepo,
		userRepo:   userRepo,
		auditRepo:  auditRepo,
		cache:      cache,
		logger:     logger,
	}
}

func (s *staffService) CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("first_name", staff.FirstName).
			Str("last_name", staff.LastName).
			Msg("CreateStaffMember completed")
	}()

	// Validate required fields
	if staff.ClinicID == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}
	if staff.UserID == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}
	if staff.FirstName == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "First name is required", 400)
	}
	if staff.LastName == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Last name is required", 400)
	}
	if staff.StaffRole == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Staff role is required", 400)
	}

	// Verify clinic exists
	if _, err := s.clinicRepo.GetClinicByID(ctx, staff.ClinicID); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		s.logger.Error().Err(err).Str("clinic_id", staff.ClinicID.String()).Msg("Failed to get clinic")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify clinic", 500)
	}

	// Verify user exists
	if _, err := s.userRepo.GetUserByID(ctx, staff.UserID); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", staff.UserID.String()).Msg("Failed to get user")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify user", 500)
	}

	// Set timestamps and status
	now := time.Now()
	staff.ID = uuid.New()
	staff.EmploymentStatus = "active"
	staff.CreatedAt = now
	staff.UpdatedAt = now

	// Create staff member
	createdStaff, err := s.staffRepo.CreateStaffMember(ctx, staff)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateUserStaff) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "User is already a staff member", 409)
		}
		if errors.Is(err, domain.ErrDuplicateStaffEmail) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "Work email already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicateHPCSNumber) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "HPCS number already exists", 409)
		}
		s.logger.Error().Err(err).
			Str("user_id", staff.UserID.String()).
			Str("clinic_id", staff.ClinicID.String()).
			Msg("Failed to create staff member")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to create staff member", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, createdStaff.ID, createdStaff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_created", createdStaff.ID, createdStaff.UserID, map[string]interface{}{
		"clinic_id":  createdStaff.ClinicID,
		"staff_role": createdStaff.StaffRole,
		"first_name": createdStaff.FirstName,
		"last_name":  createdStaff.LastName,
	})

	s.logger.Info().
		Str("staff_id", createdStaff.ID.String()).
		Str("user_id", createdStaff.UserID.String()).
		Str("clinic_id", createdStaff.ClinicID.String()).
		Str("role", createdStaff.StaffRole).
		Msg("Staff member created successfully")

	return createdStaff, nil
}

func (s *staffService) GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", id.String()).
			Msg("GetStaffByID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("staff:%s", id.String())
	var staff providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().Str("staff_id", id.String()).Msg("Staff retrieved from cache")
		return staff, nil
	}

	// Fetch from database
	staff, err := s.staffRepo.GetStaffByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to get staff member")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, staff, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache staff")
	}

	return staff, nil
}

func (s *staffService) UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", staff.ID.String()).
			Msg("UpdateStaffMember completed")
	}()

	// Validate required fields
	if staff.FirstName == "" {
		return domain.NewAppError(domain.ErrValidation, "First name is required", 400)
	}
	if staff.LastName == "" {
		return domain.NewAppError(domain.ErrValidation, "Last name is required", 400)
	}

	// Get existing staff to compare changes
	existing, err := s.staffRepo.GetStaffByID(ctx, staff.ID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		return domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Update staff member
	if err := s.staffRepo.UpdateStaffMember(ctx, staff); err != nil {
		s.logger.Error().Err(err).Str("staff_id", staff.ID.String()).Msg("Failed to update staff member")
		return domain.NewAppError(err, "Failed to update staff member", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, staff.ID, staff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_updated", staff.ID, staff.UserID, map[string]interface{}{
		"clinic_id": staff.ClinicID,
		"changes":   s.compareStaffChanges(existing, staff),
	})

	s.logger.Info().
		Str("staff_id", staff.ID.String()).
		Str("first_name", staff.FirstName).
		Str("last_name", staff.LastName).
		Msg("Staff member updated successfully")

	return nil
}

func (s *staffService) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", id.String()).
			Msg("DeleteStaffMember completed")
	}()

	// Get staff first for audit logging
	staff, err := s.staffRepo.GetStaffByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrStaffNotFound) {
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to get staff member for deletion")
		return domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Delete staff member
	if err := s.staffRepo.DeleteStaffMember(ctx, id); err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to delete staff member")
		return domain.NewAppError(err, "Failed to delete staff member", 500)
	}

	// Invalidate cache
	if staff.ID != uuid.Nil {
		s.invalidateStaffCache(ctx, staff.ID, staff.ClinicID)
	}

	// Log audit activity
	if staff.ID != uuid.Nil {
		s.logStaffActivity(ctx, "staff_deleted", id, staff.UserID, map[string]interface{}{
			"clinic_id":  staff.ClinicID,
			"first_name": staff.FirstName,
			"last_name":  staff.LastName,
		})
	}

	s.logger.Info().
		Str("staff_id", id.String()).
		Msg("Staff member deleted successfully")

	return nil
}

func (s *staffService) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Str("role", stringPtrToString(role)).
			Msg("GetClinicStaff completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("staff:clinic:%s:role:%s", clinicID.String(), stringPtrToString(role))
	var staff []providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Clinic staff retrieved from cache")
		return staff, nil
	}

	// Get clinic staff
	staff, err := s.staffRepo.GetClinicStaff(ctx, clinicID, role)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get clinic staff")
		return nil, domain.NewAppError(err, "Failed to get clinic staff", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, staff, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache clinic staff")
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("staff_count", len(staff)).
		Msg("Clinic staff retrieved")

	return staff, nil
}

func (s *staffService) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetActiveClinicStaff completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("staff:clinic:%s:active", clinicID.String())
	var staff []providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Active clinic staff retrieved from cache")
		return staff, nil
	}

	// Get active clinic staff
	staff, err := s.staffRepo.GetActiveClinicStaff(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get active clinic staff")
		return nil, domain.NewAppError(err, "Failed to get active clinic staff", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, staff, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache active clinic staff")
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("active_staff_count", len(staff)).
		Msg("Active clinic staff retrieved")

	return staff, nil
}

func (s *staffService) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", id.String()).
			Msg("StaffExists completed")
	}()

	exists, err := s.staffRepo.StaffExists(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to check if staff exists")
		return false, domain.NewAppError(err, "Failed to check staff existence", 500)
	}

	return exists, nil
}

// Helper methods
func (s *staffService) invalidateStaffCache(ctx context.Context, staffID, clinicID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("staff:%s", staffID.String()),
		fmt.Sprintf("staff:user:*"), // Need user ID to be more specific
		fmt.Sprintf("staff:clinic:%s:*", clinicID.String()),
	}

	for _, pattern := range cacheKeys {
		// Note: This requires cache implementation with pattern matching support
		s.logger.Debug().Str("pattern", pattern).Msg("Would invalidate staff cache pattern")
	}
}

func (s *staffService) logStaffActivity(ctx context.Context, activityType string, staffID, userID uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          &userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("staff"),
		ResourceID:      &staffID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to log staff activity")
		}
	}()
}

func (s *staffService) compareStaffChanges(oldStaff, newStaff providers.ClinicStaff) map[string]interface{} {
	changes := make(map[string]interface{})

	if oldStaff.FirstName != newStaff.FirstName {
		changes["first_name"] = map[string]string{
			"old": oldStaff.FirstName,
			"new": newStaff.FirstName,
		}
	}
	if oldStaff.LastName != newStaff.LastName {
		changes["last_name"] = map[string]string{
			"old": oldStaff.LastName,
			"new": newStaff.LastName,
		}
	}
	if stringPtrToString(oldStaff.ProfessionalTitle) != stringPtrToString(newStaff.ProfessionalTitle) {
		changes["professional_title"] = map[string]string{
			"old": stringPtrToString(oldStaff.ProfessionalTitle),
			"new": stringPtrToString(newStaff.ProfessionalTitle),
		}
	}
	// Add more field comparisons as needed

	return changes
}
