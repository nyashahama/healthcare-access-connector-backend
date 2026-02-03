package patients

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type dependentHealthRecordService struct {
	dependentHealthRepo repository.DependentHealthRecordRepository
	dependentRepo       repository.PatientDependentRepository
	cache               cache.Service
	logger              *zerolog.Logger
}

// NewDependentHealthRecordService creates a new dependent health record service
func NewDependentHealthRecordService(
	dependentHealthRepo repository.DependentHealthRecordRepository,
	dependentRepo repository.PatientDependentRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.DependentHealthRecordService {
	return &dependentHealthRecordService{
		dependentHealthRepo: dependentHealthRepo,
		dependentRepo:       dependentRepo,
		cache:               cache,
		logger:              logger,
	}
}

// AddDependentHealthRecord adds a new health record for a dependent
func (s *dependentHealthRecordService) AddDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) (patients.DependentHealthRecord, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("dependent_id", record.DependentID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add dependent health record completed")
	}()

	// Validate input
	if err := s.validateDependentHealthRecord(record); err != nil {
		return patients.DependentHealthRecord{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify dependent exists
	_, err := s.dependentRepo.GetPatientDependents(ctx, record.DependentID)
	if err != nil {
		s.logger.Error().Err(err).Str("dependent_id", record.DependentID.String()).Msg("Failed to verify dependent")
		return patients.DependentHealthRecord{}, domain.NewAppError(err, "Failed to verify dependent", 500)
	}

	// Set timestamps
	now := time.Now()
	record.ID = uuid.New()
	record.CreatedAt = now

	// Add health record
	created, err := s.dependentHealthRepo.AddDependentHealthRecord(ctx, record)
	if err != nil {
		s.logger.Error().Err(err).
			Str("dependent_id", record.DependentID.String()).
			Str("record_type", s.recordTypeToString(record.RecordType)).
			Msg("Failed to add dependent health record")
		return patients.DependentHealthRecord{}, domain.NewAppError(err, "Failed to add dependent health record", 500)
	}

	// Invalidate cache
	s.invalidateDependentHealthCache(ctx, record.DependentID)

	s.logger.Info().
		Str("health_record_id", created.ID.String()).
		Str("dependent_id", created.DependentID.String()).
		Str("record_type", s.recordTypeToString(created.RecordType)).
		Time("record_date", created.RecordDate).
		Msg("Dependent health record added successfully")

	return created, nil
}

// GetDependentHealthRecords retrieves all health records for a dependent
func (s *dependentHealthRecordService) GetDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("dependent_id", dependentID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get dependent health records completed")
	}()

	// Verify dependent exists
	_, err := s.dependentRepo.GetPatientDependents(ctx, dependentID)
	if err != nil {
		s.logger.Error().Err(err).Str("dependent_id", dependentID.String()).Msg("Failed to verify dependent")
		return nil, domain.NewAppError(err, "Failed to verify dependent", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("dependent_health:all:%s", dependentID.String())
	var records []patients.DependentHealthRecord
	if err := s.cache.Get(ctx, cacheKey, &records); err == nil {
		s.logger.Debug().Str("dependent_id", dependentID.String()).Msg("Dependent health records retrieved from cache")
		return records, nil
	}

	// Fetch from database
	records, err = s.dependentHealthRepo.GetDependentHealthRecords(ctx, dependentID)
	if err != nil {
		s.logger.Error().Err(err).Str("dependent_id", dependentID.String()).Msg("Failed to get dependent health records")
		return nil, domain.NewAppError(err, "Failed to get dependent health records", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, records, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache dependent health records")
	}

	s.logger.Debug().
		Str("dependent_id", dependentID.String()).
		Int("count", len(records)).
		Msg("Dependent health records retrieved successfully")

	return records, nil
}

// GetGrowthRecords retrieves growth records for a dependent
func (s *dependentHealthRecordService) GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("dependent_id", dependentID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get growth records completed")
	}()

	// Verify dependent exists
	_, err := s.dependentRepo.GetPatientDependents(ctx, dependentID)
	if err != nil {
		s.logger.Error().Err(err).Str("dependent_id", dependentID.String()).Msg("Failed to verify dependent")
		return nil, domain.NewAppError(err, "Failed to verify dependent", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("dependent_health:growth:%s", dependentID.String())
	var records []patients.DependentHealthRecord
	if err := s.cache.Get(ctx, cacheKey, &records); err == nil {
		s.logger.Debug().Str("dependent_id", dependentID.String()).Msg("Growth records retrieved from cache")
		return records, nil
	}

	// Fetch from database
	records, err = s.dependentHealthRepo.GetGrowthRecords(ctx, dependentID)
	if err != nil {
		s.logger.Error().Err(err).Str("dependent_id", dependentID.String()).Msg("Failed to get growth records")
		return nil, domain.NewAppError(err, "Failed to get growth records", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, records, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache growth records")
	}

	s.logger.Debug().
		Str("dependent_id", dependentID.String()).
		Int("count", len(records)).
		Msg("Growth records retrieved successfully")

	return records, nil
}

// UpdateDependentHealthRecord updates a dependent health record
func (s *dependentHealthRecordService) UpdateDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("health_record_id", record.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update dependent health record completed")
	}()

	// Validate input
	if err := s.validateDependentHealthRecord(record); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing health records for the dependent to verify ownership
	allRecords, err := s.dependentHealthRepo.GetDependentHealthRecords(ctx, record.DependentID)
	if err != nil {
		s.logger.Error().Err(err).Str("dependent_id", record.DependentID.String()).Msg("Failed to get dependent health records")
		return domain.NewAppError(err, "Failed to get dependent health records", 500)
	}

	// Find the health record
	var found bool
	for _, existing := range allRecords {
		if existing.ID == record.ID {
			found = true
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("health_record_id", record.ID.String()).
			Str("dependent_id", record.DependentID.String()).
			Msg("Health record not found for dependent")
		return domain.NewAppError(domain.ErrNotFound, "Health record not found for this dependent", 404)
	}

	// Update health record
	if err := s.dependentHealthRepo.UpdateDependentHealthRecord(ctx, record); err != nil {
		s.logger.Error().Err(err).
			Str("health_record_id", record.ID.String()).
			Str("dependent_id", record.DependentID.String()).
			Msg("Failed to update dependent health record")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Health record not found", 404)
		}
		return domain.NewAppError(err, "Failed to update dependent health record", 500)
	}

	// Invalidate cache
	s.invalidateDependentHealthCache(ctx, record.DependentID)

	s.logger.Info().
		Str("health_record_id", record.ID.String()).
		Str("dependent_id", record.DependentID.String()).
		Msg("Dependent health record updated successfully")

	return nil
}

// DeleteDependentHealthRecord deletes a dependent health record
func (s *dependentHealthRecordService) DeleteDependentHealthRecord(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("health_record_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete dependent health record completed")
	}()

	// Delete health record
	if err := s.dependentHealthRepo.DeleteDependentHealthRecord(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("health_record_id", id.String()).Msg("Failed to delete dependent health record")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Health record not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete dependent health record", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the dependent ID.
	// In a production system, you would add a GetDependentHealthRecordByID method.

	s.logger.Info().Str("health_record_id", id.String()).Msg("Dependent health record deleted successfully")
	return nil
}

// Validate dependent health record
func (s *dependentHealthRecordService) validateDependentHealthRecord(record patients.DependentHealthRecord) error {
	if record.DependentID == uuid.Nil {
		return fmt.Errorf("dependent ID is required")
	}
	if record.RecordDate.IsZero() {
		return fmt.Errorf("record date is required")
	}
	if record.RecordDate.After(time.Now()) {
		return fmt.Errorf("record date cannot be in the future")
	}

	// Validate numeric values
	if record.WeightKg != nil && *record.WeightKg <= 0 {
		return fmt.Errorf("weight must be positive")
	}

	if record.HeightCm != nil && *record.HeightCm <= 0 {
		return fmt.Errorf("height must be positive")
	}

	if record.HeadCircumferenceCm != nil && *record.HeadCircumferenceCm <= 0 {
		return fmt.Errorf("head circumference must be positive")
	}

	if record.TemperatureC != nil && (*record.TemperatureC < 35 || *record.TemperatureC > 42) {
		return fmt.Errorf("temperature must be between 35 and 42 degrees Celsius")
	}

	// Validate next appointment date if provided
	if record.NextAppointmentDate != nil && record.NextAppointmentDate.Before(record.RecordDate) {
		return fmt.Errorf("next appointment date cannot be before record date")
	}

	return nil
}

// Helper methods
func (s *dependentHealthRecordService) invalidateDependentHealthCache(ctx context.Context, dependentID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("dependent_health:all:%s", dependentID.String()),
		fmt.Sprintf("dependent_health:growth:%s", dependentID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate dependent health cache")
		}
	}
}

func (s *dependentHealthRecordService) recordTypeToString(recordType *string) string {
	if recordType == nil {
		return "unknown"
	}
	return *recordType
}
