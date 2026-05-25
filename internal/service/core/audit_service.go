package core

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type auditService struct {
	auditRepo repository.AuditRepository
	userRepo  repository.UserRepository
	cache     cache.Service
	logger    *zerolog.Logger
}

func (s *auditService) cacheAvailable() bool {
	return s != nil && s.cache != nil && s.cache.IsAvailable()
}

// NewAuditService creates a new audit service
func NewAuditService(
	auditRepo repository.AuditRepository,
	userRepo repository.UserRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.AuditService {
	return &auditService{
		auditRepo: auditRepo,
		userRepo:  userRepo,
		cache:     cache,
		logger:    logger,
	}
}

// LogUserActivity logs user activity for auditing
func (s *auditService) LogUserActivity(ctx context.Context, activity core.UserActivity) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("activity_type", activity.ActivityType).
			Str("user_id", uuidToString(activity.UserID)).
			Msg("LogUserActivity completed")
	}()

	// Set timestamp if not provided
	if activity.PerformedAt.IsZero() {
		activity.PerformedAt = time.Now()
	}

	// Log the activity
	if err := s.auditRepo.LogUserActivity(ctx, activity); err != nil {
		s.logger.Error().Err(err).
			Str("activity_type", activity.ActivityType).
			Str("user_id", uuidToString(activity.UserID)).
			Msg("Failed to log user activity")
		return domain.NewAppError(err, "Failed to log activity", 500)
	}

	s.logger.Info().
		Str("activity_type", activity.ActivityType).
		Str("user_id", uuidToString(activity.UserID)).
		Msg("User activity logged")

	return nil
}

// GetUserActivities retrieves activities for a user
func (s *auditService) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Int("limit", limit).
			Int("offset", offset).
			Msg("GetUserActivities completed")
	}()

	// Validate input
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Try cache first
	cacheKey := fmt.Sprintf("audit:activities:%s:%d:%d", userID.String(), limit, offset)
	var activities []core.UserActivity
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &activities); err == nil {
			s.logger.Debug().Str("user_id", userID.String()).Msg("User activities retrieved from cache")
			return activities, nil
		}
	}

	// Fetch from database
	activities, err := s.auditRepo.GetUserActivities(ctx, userID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user activities")
		return nil, domain.NewAppError(err, "Failed to get user activities", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, activities, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache user activities")
		}
	}

	s.logger.Debug().
		Str("user_id", userID.String()).
		Int("count", len(activities)).
		Msg("User activities retrieved")

	return activities, nil
}

// LogDataAccess logs data access for auditing
func (s *auditService) LogDataAccess(ctx context.Context, access core.DataAccessLog) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("access_type", access.AccessType).
			Str("accessed_user_id", access.AccessedUserID.String()).
			Str("accessed_by", uuidToString(access.AccessedByUserID)).
			Msg("LogDataAccess completed")
	}()

	// Set timestamp if not provided
	if access.AccessedAt.IsZero() {
		access.AccessedAt = time.Now()
	}

	// Log the access
	if err := s.auditRepo.LogDataAccess(ctx, access); err != nil {
		s.logger.Error().Err(err).
			Str("access_type", access.AccessType).
			Str("accessed_user_id", access.AccessedUserID.String()).
			Msg("Failed to log data access")
		return domain.NewAppError(err, "Failed to log data access", 500)
	}

	s.logger.Info().
		Str("access_type", access.AccessType).
		Str("accessed_user_id", access.AccessedUserID.String()).
		Str("accessed_by", uuidToString(access.AccessedByUserID)).
		Bool("emergency", access.IsEmergencyAccess).
		Msg("Data access logged")

	return nil
}

func uuidToString(id *uuid.UUID) string {
	if id == nil {
		return "nil"
	}
	return id.String()
}
