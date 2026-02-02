package admin

import (
	"context"
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

	// Log activity
	if s.auditService != nil {
		systemIP := "system"
		go s.auditService.LogUserActivity(ctx, core.UserActivity{
			UserID:       &sysAdmin.UserID,
			ActivityType: "system_admin_created",
			ActivityDetails: map[string]interface{}{
				"description": fmt.Sprintf("System admin profile created with level: %s", sysAdmin.AdminLevel),
				"admin_level": sysAdmin.AdminLevel,
				"department":  sysAdmin.Department,
			},
			IPAddress:   &systemIP,
			PerformedAt: now,
		})
	}

	s.logger.Info().
		Str("user_id", created.UserID.String()).
		Str("admin_level", created.AdminLevel).
		Msg("System admin created successfully")

	return created, nil
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
