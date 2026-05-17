package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type systemAdminService struct {
	sysAdminRepo repository.SystemAdminRepository
	userRepo     repository.UserRepository
	auditService service.AuditService
	cache        cache.Service
	logger       *zerolog.Logger
}

// NewSystemAdminService creates a new system admin service
func NewSystemAdminService(
	sysAdminRepo repository.SystemAdminRepository,
	userRepo repository.UserRepository,
	auditService service.AuditService,
	cache cache.Service,
	logger *zerolog.Logger,
) service.SystemAdminService {
	return &systemAdminService{
		sysAdminRepo: sysAdminRepo,
		userRepo:     userRepo,
		auditService: auditService,
		cache:        cache,
		logger:       logger,
	}
}

// CreateSystemAdmin creates a new system admin profile
func (s *systemAdminService) CreateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", sysAdmin.UserID.String()).
			Msg("CreateSystemAdmin completed")
	}()

	// Validate that the user exists and has system_admin role
	user, err := s.userRepo.GetUserByID(ctx, sysAdmin.UserID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", sysAdmin.UserID.String()).Msg("Failed to get user")
		return admin.SystemAdmin{}, domain.NewAppError(err, "User not found", 404)
	}

	if user.Role != "system_admin" {
		s.logger.Warn().
			Str("user_id", sysAdmin.UserID.String()).
			Str("role", user.Role).
			Msg("User is not a system admin")
		return admin.SystemAdmin{}, domain.NewAppError(domain.ErrValidation, "User must have system_admin role", 400)
	}

	// Validate admin level
	validLevels := map[string]bool{
		"super_admin":  true,
		"regional":     true,
		"departmental": true,
		"support":      true,
	}
	if !validLevels[sysAdmin.AdminLevel] {
		return admin.SystemAdmin{}, domain.NewAppError(domain.ErrValidation, "Invalid admin level", 400)
	}

	// Set timestamps
	now := time.Now()
	sysAdmin.CreatedAt = now
	sysAdmin.UpdatedAt = now

	// Create system admin
	created, err := s.sysAdminRepo.CreateSystemAdmin(ctx, sysAdmin)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to create system admin")
		return admin.SystemAdmin{}, domain.NewAppError(err, "Failed to create system admin", 500)
	}

	// Invalidate cache
	s.invalidateSystemAdminCache(ctx, created.UserID)

	// Log activity using helper method
	s.logActivityAsync(
		&created.UserID,
		"system_admin_created",
		map[string]interface{}{
			"description":     fmt.Sprintf("System admin profile created with level: %s", created.AdminLevel),
			"admin_level":     created.AdminLevel,
			"department":      created.Department,
			"system_admin_id": created.ID.String(),
		},
		stringPtr("system_admin"),
		&created.ID,
	)

	s.logger.Info().
		Str("user_id", created.UserID.String()).
		Str("admin_level", created.AdminLevel).
		Msg("System admin created successfully")

	return created, nil
}

// GetSystemAdminByUserID gets system admin by user ID
func (s *systemAdminService) GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetSystemAdminByUserID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("system_admin:user:%s", userID.String())
	var sysAdmin admin.SystemAdmin
	if err := s.cache.Get(ctx, cacheKey, &sysAdmin); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("System admin retrieved from cache")
		return sysAdmin, nil
	}

	// Fetch from database
	sysAdmin, err := s.sysAdminRepo.GetSystemAdminByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return admin.SystemAdmin{}, domain.NewAppError(domain.ErrNotFound, "System admin not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get system admin")
		return admin.SystemAdmin{}, domain.NewAppError(err, "Failed to get system admin", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, sysAdmin, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache system admin")
	}

	return sysAdmin, nil
}

// GetSystemAdmin gets system admin by ID
func (s *systemAdminService) GetSystemAdmin(ctx context.Context, id uuid.UUID) (admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("system_admin_id", id.String()).
			Msg("GetSystemAdmin completed")
	}()

	if id == uuid.Nil {
		s.logger.Warn().Msg("GetSystemAdmin called with nil ID")
		return admin.SystemAdmin{}, domain.NewAppError(domain.ErrValidation, "System admin ID is required", 400)
	}

	sysAdmin, err := s.sysAdminRepo.GetSystemAdmin(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return admin.SystemAdmin{}, domain.NewAppError(domain.ErrNotFound, "System admin not found", 404)
		}
		s.logger.Error().Err(err).Str("system_admin_id", id.String()).Msg("Failed to get system admin")
		return admin.SystemAdmin{}, domain.NewAppError(err, "Failed to get system admin", 500)
	}

	return sysAdmin, nil
}

// UpdateSystemAdmin updates system admin profile
func (s *systemAdminService) UpdateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("system_admin_id", sysAdmin.ID.String()).
			Msg("UpdateSystemAdmin completed")
	}()

	if sysAdmin.ID == uuid.Nil {
		return admin.SystemAdmin{}, domain.NewAppError(domain.ErrValidation, "System admin ID is required", 400)
	}

	existing, err := s.sysAdminRepo.GetSystemAdmin(ctx, sysAdmin.ID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return admin.SystemAdmin{}, domain.NewAppError(domain.ErrNotFound, "System admin not found", 404)
		}
		s.logger.Error().Err(err).Str("system_admin_id", sysAdmin.ID.String()).Msg("Failed to get existing system admin")
		return admin.SystemAdmin{}, domain.NewAppError(err, "Failed to update system admin", 500)
	}

	if sysAdmin.AdminLevel != "" && !isValidAdminLevel(sysAdmin.AdminLevel) {
		return admin.SystemAdmin{}, domain.NewAppError(domain.ErrValidation, "Invalid admin level", 400)
	}

	sysAdmin.UserID = existing.UserID
	sysAdmin.CreatedAt = existing.CreatedAt
	sysAdmin.UpdatedAt = time.Now()

	if sysAdmin.AdminLevel == "" {
		sysAdmin.AdminLevel = existing.AdminLevel
	}
	if sysAdmin.AssignedRegions == nil {
		sysAdmin.AssignedRegions = existing.AssignedRegions
	}
	if sysAdmin.Department == nil {
		sysAdmin.Department = existing.Department
	}
	if sysAdmin.Permissions == nil {
		sysAdmin.Permissions = existing.Permissions
	}
	if sysAdmin.WorkPhone == nil {
		sysAdmin.WorkPhone = existing.WorkPhone
	}
	if sysAdmin.Extension == nil {
		sysAdmin.Extension = existing.Extension
	}

	if err := s.sysAdminRepo.UpdateSystemAdmin(ctx, sysAdmin); err != nil {
		s.logger.Error().Err(err).Str("system_admin_id", sysAdmin.ID.String()).Msg("Failed to update system admin")
		return admin.SystemAdmin{}, domain.NewAppError(err, "Failed to update system admin", 500)
	}

	// Invalidate cache
	s.invalidateSystemAdminCache(ctx, existing.UserID)

	updated, err := s.sysAdminRepo.GetSystemAdmin(ctx, sysAdmin.ID)
	if err != nil {
		s.logger.Error().Err(err).Str("system_admin_id", sysAdmin.ID.String()).Msg("Failed to load updated system admin")
		return admin.SystemAdmin{}, domain.NewAppError(err, "Failed to fetch updated system admin", 500)
	}

	s.logActivityAsync(
		&updated.UserID,
		"system_admin_updated",
		map[string]interface{}{
			"description":     "System admin profile updated",
			"system_admin_id": updated.ID.String(),
		},
		stringPtr("system_admin"),
		&updated.ID,
	)

	s.logger.Info().Str("system_admin_id", updated.ID.String()).Msg("System admin updated successfully")

	return updated, nil
}

// DeleteSystemAdmin removes system admin by system admin ID
func (s *systemAdminService) DeleteSystemAdmin(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("system_admin_id", id.String()).
			Msg("DeleteSystemAdmin completed")
	}()

	if id == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "System admin ID is required", 400)
	}

	existing, err := s.sysAdminRepo.GetSystemAdmin(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "System admin not found", 404)
		}
		s.logger.Error().Err(err).Str("system_admin_id", id.String()).Msg("Failed to find system admin")
		return domain.NewAppError(err, "Failed to delete system admin", 500)
	}

	if err := s.sysAdminRepo.DeleteSystemAdmin(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("system_admin_id", id.String()).Msg("Failed to delete system admin")
		return domain.NewAppError(err, "Failed to delete system admin", 500)
	}

	s.invalidateSystemAdminCache(ctx, existing.UserID)

	s.logActivityAsync(
		&existing.UserID,
		"system_admin_deleted",
		map[string]interface{}{
			"description":     "System admin profile deleted",
			"system_admin_id": existing.ID.String(),
		},
		stringPtr("system_admin"),
		&existing.ID,
	)

	s.logger.Info().Str("system_admin_id", id.String()).Msg("System admin deleted successfully")
	return nil
}

// DeleteSystemAdminByUserID removes system admin by user ID
func (s *systemAdminService) DeleteSystemAdminByUserID(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("DeleteSystemAdminByUserID completed")
	}()

	if userID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	existing, err := s.sysAdminRepo.GetSystemAdminByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "System admin not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to find system admin")
		return domain.NewAppError(err, "Failed to delete system admin", 500)
	}

	if err := s.sysAdminRepo.DeleteSystemAdminByUserID(ctx, userID); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to delete system admin")
		return domain.NewAppError(err, "Failed to delete system admin", 500)
	}

	s.invalidateSystemAdminCache(ctx, userID)

	s.logActivityAsync(
		&userID,
		"system_admin_deleted",
		map[string]interface{}{
			"description":     "System admin profile deleted by user ID",
			"system_admin_id": existing.ID.String(),
			"user_id":        userID.String(),
		},
		stringPtr("system_admin"),
		&existing.ID,
	)

	s.logger.Info().
		Str("system_admin_id", existing.ID.String()).
		Str("user_id", userID.String()).
		Msg("System admin deleted successfully by user ID")
	return nil
}

// SearchSystemAdmins searches system admins using filters
func (s *systemAdminService) SearchSystemAdmins(ctx context.Context, params admin.SystemAdminSearchParams) ([]admin.SystemAdmin, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("SearchSystemAdmins completed")
	}()

	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if params.Offset < 0 {
		params.Offset = 0
	}
	params.Limit = limit

	result, err := s.sysAdminRepo.SearchSystemAdmins(ctx, params)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to search system admins")
		return nil, domain.NewAppError(err, "Failed to search system admins", 500)
	}

	return result, nil
}

// Helper method for asynchronous activity logging
func (s *systemAdminService) logActivityAsync(userID *uuid.UUID, activityType string, details map[string]interface{}, resourceType *string, resourceID *uuid.UUID) {
	if s.auditService == nil {
		return
	}

	go func() {
		// Create a new background context with timeout
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Validate and sanitize the details map to ensure JSON serialization works
		cleanDetails := sanitizeActivityDetails(details)

		systemIP := "system"
		activity := core.UserActivity{
			UserID:          userID,
			ActivityType:    activityType,
			ActivityDetails: cleanDetails,
			ResourceType:    resourceType,
			ResourceID:      resourceID,
			IPAddress:       &systemIP,
			PerformedAt:     time.Now(),
		}

		if err := s.auditService.LogUserActivity(auditCtx, activity); err != nil {
			// Log the failure but don't fail the main operation
			s.logger.Warn().
				Err(err).
				Str("activity_type", activityType).
				Str("user_id", uuidToString(userID)).
				Msg("Failed to log activity")
		}
	}()
}

// Helper methods

func (s *systemAdminService) invalidateSystemAdminCache(ctx context.Context, userID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}

	cacheKeys := []string{
		fmt.Sprintf("system_admin:user:%s", userID.String()),
		fmt.Sprintf("system_admin:permissions:%s", userID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate cache")
		}
	}
}

func isValidAdminLevel(level string) bool {
	validLevels := map[string]bool{
		"super_admin":  true,
		"regional":     true,
		"departmental": true,
		"support":      true,
	}
	return validLevels[level]
}

// sanitizeActivityDetails ensures all values in the details map are JSON-serializable
func sanitizeActivityDetails(details map[string]interface{}) map[string]any {
	if details == nil {
		return make(map[string]any)
	}

	// Create a clean map and verify JSON serialization
	cleanDetails := make(map[string]any)
	for k, v := range details {
		// Ensure each value is JSON-serializable
		if isJSONSerializable(v) {
			cleanDetails[k] = v
		} else {
			// Convert non-serializable values to strings
			cleanDetails[k] = fmt.Sprintf("%v", v)
		}
	}

	// Double-check by attempting to marshal
	if _, err := json.Marshal(cleanDetails); err != nil {
		// If marshaling fails, return a safe fallback
		return map[string]any{
			"error": "Failed to serialize activity details",
		}
	}

	return cleanDetails
}

// isJSONSerializable checks if a value can be JSON serialized
func isJSONSerializable(v interface{}) bool {
	switch v.(type) {
	case nil, bool, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, string:
		return true
	case []interface{}, map[string]interface{}:
		// For complex types, try to marshal
		_, err := json.Marshal(v)
		return err == nil
	default:
		// For other types, try to marshal
		_, err := json.Marshal(v)
		return err == nil
	}
}

// Helper functions

func stringPtr(s string) *string {
	return &s
}

func uuidToString(id *uuid.UUID) string {
	if id == nil {
		return "nil"
	}
	return id.String()
}
