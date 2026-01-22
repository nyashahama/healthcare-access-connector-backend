package core

import (
	"context"
	"encoding/json"
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
	if err := s.cache.Get(ctx, cacheKey, &activities); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("User activities retrieved from cache")
		return activities, nil
	}

	// Fetch from database
	activities, err := s.auditRepo.GetUserActivities(ctx, userID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user activities")
		return nil, domain.NewAppError(err, "Failed to get user activities", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, activities, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache user activities")
	}

	s.logger.Debug().
		Str("user_id", userID.String()).
		Int("count", len(activities)).
		Msg("User activities retrieved")

	return activities, nil
}

// GetActivitiesByType retrieves activities by type within a date range
func (s *auditService) GetActivitiesByType(ctx context.Context, activityType string, startDate, endDate time.Time) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("activity_type", activityType).
			Time("start_date", startDate).
			Time("end_date", endDate).
			Msg("GetActivitiesByType completed")
	}()

	// Validate date range
	if startDate.After(endDate) {
		return nil, domain.NewAppError(domain.ErrValidation, "Start date must be before end date", 400)
	}

	// Limit date range to 30 days for performance
	if endDate.Sub(startDate) > 30*24*time.Hour {
		endDate = startDate.Add(30 * 24 * time.Hour)
		s.logger.Warn().
			Str("activity_type", activityType).
			Msg("Date range limited to 30 days for performance")
	}

	// Fetch activities
	activities, err := s.auditRepo.GetActivitiesByType(ctx, activityType, startDate, endDate)
	if err != nil {
		s.logger.Error().Err(err).Str("activity_type", activityType).Msg("Failed to get activities by type")
		return nil, domain.NewAppError(err, "Failed to get activities", 500)
	}

	s.logger.Debug().
		Str("activity_type", activityType).
		Int("count", len(activities)).
		Msg("Activities by type retrieved")

	return activities, nil
}

// GetActivitiesByResource retrieves activities for a specific resource
func (s *auditService) GetActivitiesByResource(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("resource_type", resourceType).
			Str("resource_id", resourceID.String()).
			Msg("GetActivitiesByResource completed")
	}()

	// Fetch activities
	activities, err := s.auditRepo.GetActivitiesByResource(ctx, resourceType, resourceID)
	if err != nil {
		s.logger.Error().Err(err).
			Str("resource_type", resourceType).
			Str("resource_id", resourceID.String()).
			Msg("Failed to get activities by resource")
		return nil, domain.NewAppError(err, "Failed to get activities", 500)
	}

	s.logger.Debug().
		Str("resource_type", resourceType).
		Str("resource_id", resourceID.String()).
		Int("count", len(activities)).
		Msg("Activities by resource retrieved")

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

// GetDataAccessLogs retrieves data access logs for a user
func (s *auditService) GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("accessed_user_id", accessedUserID.String()).
			Int("limit", limit).
			Int("offset", offset).
			Msg("GetDataAccessLogs completed")
	}()

	// Validate input
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Fetch access logs
	logs, err := s.auditRepo.GetDataAccessLogs(ctx, accessedUserID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("accessed_user_id", accessedUserID.String()).Msg("Failed to get data access logs")
		return nil, domain.NewAppError(err, "Failed to get data access logs", 500)
	}

	s.logger.Debug().
		Str("accessed_user_id", accessedUserID.String()).
		Int("count", len(logs)).
		Msg("Data access logs retrieved")

	return logs, nil
}

// GetDataAccessLogsByAccessor retrieves data access logs by accessor
func (s *auditService) GetDataAccessLogsByAccessor(ctx context.Context, accessedByUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("accessed_by_user_id", accessedByUserID.String()).
			Int("limit", limit).
			Int("offset", offset).
			Msg("GetDataAccessLogsByAccessor completed")
	}()

	// Validate input
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Fetch access logs
	logs, err := s.auditRepo.GetDataAccessLogsByAccessor(ctx, accessedByUserID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("accessed_by_user_id", accessedByUserID.String()).Msg("Failed to get data access logs by accessor")
		return nil, domain.NewAppError(err, "Failed to get data access logs", 500)
	}

	s.logger.Debug().
		Str("accessed_by_user_id", accessedByUserID.String()).
		Int("count", len(logs)).
		Msg("Data access logs by accessor retrieved")

	return logs, nil
}

// GetEmergencyAccessLogs retrieves emergency access logs
func (s *auditService) GetEmergencyAccessLogs(ctx context.Context, limit, offset int) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Int("limit", limit).
			Int("offset", offset).
			Msg("GetEmergencyAccessLogs completed")
	}()

	// Validate input
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	// Fetch emergency access logs
	logs, err := s.auditRepo.GetEmergencyAccessLogs(ctx, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get emergency access logs")
		return nil, domain.NewAppError(err, "Failed to get emergency access logs", 500)
	}

	s.logger.Debug().
		Int("count", len(logs)).
		Msg("Emergency access logs retrieved")

	return logs, nil
}

// GetAccessLogsByResourceType retrieves access logs by resource type
func (s *auditService) GetAccessLogsByResourceType(ctx context.Context, resourceType string, startDate, endDate time.Time) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("resource_type", resourceType).
			Time("start_date", startDate).
			Time("end_date", endDate).
			Msg("GetAccessLogsByResourceType completed")
	}()

	// Validate date range
	if startDate.After(endDate) {
		return nil, domain.NewAppError(domain.ErrValidation, "Start date must be before end date", 400)
	}

	// Limit date range to 30 days for performance
	if endDate.Sub(startDate) > 30*24*time.Hour {
		endDate = startDate.Add(30 * 24 * time.Hour)
		s.logger.Warn().
			Str("resource_type", resourceType).
			Msg("Date range limited to 30 days for performance")
	}

	// Fetch access logs
	logs, err := s.auditRepo.GetAccessLogsByResourceType(ctx, resourceType, startDate, endDate)
	if err != nil {
		s.logger.Error().Err(err).Str("resource_type", resourceType).Msg("Failed to get access logs by resource type")
		return nil, domain.NewAppError(err, "Failed to get access logs", 500)
	}

	s.logger.Debug().
		Str("resource_type", resourceType).
		Int("count", len(logs)).
		Msg("Access logs by resource type retrieved")

	return logs, nil
}

// GetSuspiciousActivities retrieves suspicious activities
func (s *auditService) GetSuspiciousActivities(ctx context.Context, threshold int) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Int("threshold", threshold).
			Msg("GetSuspiciousActivities completed")
	}()

	// Validate threshold
	if threshold <= 0 {
		threshold = 50
	}

	// Fetch suspicious activities
	activities, err := s.auditRepo.GetSuspiciousActivities(ctx, threshold)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get suspicious activities")
		return nil, domain.NewAppError(err, "Failed to get suspicious activities", 500)
	}

	s.logger.Debug().
		Int("threshold", threshold).
		Int("count", len(activities)).
		Msg("Suspicious activities retrieved")

	return activities, nil
}

// GetFailedLoginAttempts retrieves failed login attempts
func (s *auditService) GetFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, within time.Duration) ([]core.UserActivity, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", uuidToString(userID)).
			Dur("within", within).
			Msg("GetFailedLoginAttempts completed")
	}()

	// Validate duration
	if within <= 0 {
		within = 24 * time.Hour
	}

	// Fetch failed login attempts
	attempts, err := s.auditRepo.GetFailedLoginAttempts(ctx, userID, within)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", uuidToString(userID)).Msg("Failed to get failed login attempts")
		return nil, domain.NewAppError(err, "Failed to get failed login attempts", 500)
	}

	s.logger.Debug().
		Str("user_id", uuidToString(userID)).
		Dur("within", within).
		Int("count", len(attempts)).
		Msg("Failed login attempts retrieved")

	return attempts, nil
}

// GetUnauthorizedAccessAttempts retrieves unauthorized access attempts
func (s *auditService) GetUnauthorizedAccessAttempts(ctx context.Context, within time.Duration) ([]core.DataAccessLog, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Dur("within", within).
			Msg("GetUnauthorizedAccessAttempts completed")
	}()

	// Validate duration
	if within <= 0 {
		within = 24 * time.Hour
	}

	// Fetch unauthorized access attempts
	attempts, err := s.auditRepo.GetUnauthorizedAccessAttempts(ctx, within)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get unauthorized access attempts")
		return nil, domain.NewAppError(err, "Failed to get unauthorized access attempts", 500)
	}

	s.logger.Debug().
		Dur("within", within).
		Int("count", len(attempts)).
		Msg("Unauthorized access attempts retrieved")

	return attempts, nil
}

// ArchiveOldLogs archives old logs
func (s *auditService) ArchiveOldLogs(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Dur("older_than", olderThan).
			Msg("ArchiveOldLogs completed")
	}()

	// Validate duration (minimum 30 days)
	if olderThan < 30*24*time.Hour {
		return domain.NewAppError(domain.ErrValidation, "Archival period must be at least 30 days", 400)
	}

	// Archive old logs
	if err := s.auditRepo.ArchiveOldLogs(ctx, olderThan); err != nil {
		s.logger.Error().Err(err).Msg("Failed to archive old logs")
		return domain.NewAppError(err, "Failed to archive old logs", 500)
	}

	s.logger.Info().
		Dur("older_than", olderThan).
		Msg("Old logs archived")

	return nil
}

// DeleteArchivedLogs deletes archived logs
func (s *auditService) DeleteArchivedLogs(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Dur("older_than", olderThan).
			Msg("DeleteArchivedLogs completed")
	}()

	// Validate duration (minimum 1 year)
	if olderThan < 365*24*time.Hour {
		return domain.NewAppError(domain.ErrValidation, "Deletion period must be at least 1 year", 400)
	}

	// Delete archived logs
	if err := s.auditRepo.DeleteArchivedLogs(ctx, olderThan); err != nil {
		s.logger.Error().Err(err).Msg("Failed to delete archived logs")
		return domain.NewAppError(err, "Failed to delete archived logs", 500)
	}

	s.logger.Info().
		Dur("older_than", olderThan).
		Msg("Archived logs deleted")

	return nil
}

// ArchiveOldActivities archives old activities
func (s *auditService) ArchiveOldActivities(ctx context.Context, olderThan time.Duration) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Dur("older_than", olderThan).
			Msg("ArchiveOldActivities completed")
	}()

	// Validate duration (minimum 30 days)
	if olderThan < 30*24*time.Hour {
		return domain.NewAppError(domain.ErrValidation, "Archival period must be at least 30 days", 400)
	}

	// Archive old activities
	if err := s.auditRepo.ArchiveOldActivities(ctx, olderThan); err != nil {
		s.logger.Error().Err(err).Msg("Failed to archive old activities")
		return domain.NewAppError(err, "Failed to archive old activities", 500)
	}

	s.logger.Info().
		Dur("older_than", olderThan).
		Msg("Old activities archived")

	return nil
}

// GenerateAccessReport generates an access report for a user
func (s *auditService) GenerateAccessReport(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Time("start_date", startDate).
			Time("end_date", endDate).
			Msg("GenerateAccessReport completed")
	}()

	// Validate date range
	if startDate.After(endDate) {
		return nil, domain.NewAppError(domain.ErrValidation, "Start date must be before end date", 400)
	}

	// Limit date range to 90 days for performance
	if endDate.Sub(startDate) > 90*24*time.Hour {
		endDate = startDate.Add(90 * 24 * time.Hour)
		s.logger.Warn().
			Str("user_id", userID.String()).
			Msg("Date range limited to 90 days for performance")
	}

	// Generate report
	report, err := s.auditRepo.GenerateAccessReport(ctx, userID, startDate, endDate)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to generate access report")
		return nil, domain.NewAppError(err, "Failed to generate access report", 500)
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Time("start_date", startDate).
		Time("end_date", endDate).
		Msg("Access report generated")

	return report, nil
}

// GenerateActivityReport generates an activity report
func (s *auditService) GenerateActivityReport(ctx context.Context, startDate, endDate time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Time("start_date", startDate).
			Time("end_date", endDate).
			Msg("GenerateActivityReport completed")
	}()

	// Validate date range
	if startDate.After(endDate) {
		return nil, domain.NewAppError(domain.ErrValidation, "Start date must be before end date", 400)
	}

	// Limit date range to 30 days for performance
	if endDate.Sub(startDate) > 30*24*time.Hour {
		endDate = startDate.Add(30 * 24 * time.Hour)
		s.logger.Warn().Msg("Date range limited to 30 days for performance")
	}

	// Generate report
	report, err := s.auditRepo.GenerateActivityReport(ctx, startDate, endDate)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate activity report")
		return nil, domain.NewAppError(err, "Failed to generate activity report", 500)
	}

	s.logger.Info().
		Time("start_date", startDate).
		Time("end_date", endDate).
		Msg("Activity report generated")

	return report, nil
}

// ExportUserAuditTrail exports user audit trail
func (s *auditService) ExportUserAuditTrail(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("ExportUserAuditTrail completed")
	}()

	// Export audit trail
	data, err := s.auditRepo.ExportUserAuditTrail(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to export user audit trail")
		return nil, domain.NewAppError(err, "Failed to export audit trail", 500)
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Int("size_bytes", len(data)).
		Msg("User audit trail exported")

	return data, nil
}

// StartCleanupJob starts background cleanup job
func (s *auditService) StartCleanupJob(archiveInterval, deleteInterval time.Duration) {
	archiveTicker := time.NewTicker(archiveInterval)
	deleteTicker := time.NewTicker(deleteInterval)

	s.logger.Info().
		Dur("archive_interval", archiveInterval).
		Dur("delete_interval", deleteInterval).
		Msg("Starting audit cleanup job")

	go func() {
		for range archiveTicker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

			// Archive logs older than 30 days
			if err := s.ArchiveOldLogs(ctx, 30*24*time.Hour); err != nil {
				s.logger.Warn().Err(err).Msg("Archive job failed")
			}

			// Archive activities older than 30 days
			if err := s.ArchiveOldActivities(ctx, 30*24*time.Hour); err != nil {
				s.logger.Warn().Err(err).Msg("Activity archive job failed")
			}

			cancel()
		}
	}()

	go func() {
		for range deleteTicker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

			// Delete archived logs older than 2 years
			if err := s.DeleteArchivedLogs(ctx, 2*365*24*time.Hour); err != nil {
				s.logger.Warn().Err(err).Msg("Delete job failed")
			}

			cancel()
		}
	}()
}

// Helper functions
func uuidToString(id *uuid.UUID) string {
	if id == nil {
		return "nil"
	}
	return id.String()
}

func jsonbToMap(data []byte) map[string]interface{} {
	if len(data) == 0 {
		return make(map[string]interface{})
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return make(map[string]interface{})
	}
	return result
}

func mapToJSONB(data map[string]interface{}) ([]byte, error) {
	if data == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(data)
}
