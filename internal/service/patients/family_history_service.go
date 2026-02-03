package patients

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type familyHistoryService struct {
	familyHistoryRepo repository.PatientFamilyHistoryRepository
	patientRepo       repository.PatientProfileRepository
	cache             cache.Service
	logger            *zerolog.Logger
}

// NewFamilyHistoryService creates a new family history service
func NewFamilyHistoryService(
	familyHistoryRepo repository.PatientFamilyHistoryRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.FamilyHistoryService {
	return &familyHistoryService{
		familyHistoryRepo: familyHistoryRepo,
		patientRepo:       patientRepo,
		cache:             cache,
		logger:            logger,
	}
}

// AddFamilyHistory adds a new family history record for a patient
func (s *familyHistoryService) AddFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) (patients.PatientFamilyHistory, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", history.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add family history completed")
	}()

	// Validate input
	if err := s.validateFamilyHistory(history); err != nil {
		return patients.PatientFamilyHistory{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, history.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", history.PatientID.String()).Msg("Patient not found")
			return patients.PatientFamilyHistory{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", history.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientFamilyHistory{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Set timestamps
	now := time.Now()
	history.ID = uuid.New()
	history.CreatedAt = now

	// Add family history
	created, err := s.familyHistoryRepo.AddFamilyHistory(ctx, history)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", history.PatientID.String()).
			Str("relative", history.Relative).
			Str("condition", history.ConditionName).
			Msg("Failed to add family history")
		return patients.PatientFamilyHistory{}, domain.NewAppError(err, "Failed to add family history", 500)
	}

	// Invalidate cache
	s.invalidateFamilyHistoryCache(ctx, history.PatientID)

	s.logger.Info().
		Str("family_history_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("relative", created.Relative).
		Str("condition", created.ConditionName).
		Msg("Family history added successfully")

	return created, nil
}

// GetPatientFamilyHistory retrieves all family history records for a patient
func (s *familyHistoryService) GetPatientFamilyHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient family history completed")
	}()

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient not found")
			return nil, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to verify patient")
		return nil, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("family_history:all:%s", patientID.String())
	var histories []patients.PatientFamilyHistory
	if err := s.cache.Get(ctx, cacheKey, &histories); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient family history retrieved from cache")
		return histories, nil
	}

	// Fetch from database
	histories, err = s.familyHistoryRepo.GetPatientFamilyHistory(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient family history")
		return nil, domain.NewAppError(err, "Failed to get patient family history", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, histories, 60*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient family history")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(histories)).
		Msg("Patient family history retrieved successfully")

	return histories, nil
}

// GetFamilyHistoryByRelative retrieves family history records for a patient by relative type
func (s *familyHistoryService) GetFamilyHistoryByRelative(ctx context.Context, patientID uuid.UUID, relative string) ([]patients.PatientFamilyHistory, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Str("relative", relative).
			Dur("duration_ms", time.Since(start)).
			Msg("Get family history by relative completed")
	}()

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient not found")
			return nil, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to verify patient")
		return nil, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Validate relative
	if strings.TrimSpace(relative) == "" {
		return nil, domain.NewAppError(domain.ErrValidation, "Relative is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("family_history:relative:%s:%s", patientID.String(), relative)
	var histories []patients.PatientFamilyHistory
	if err := s.cache.Get(ctx, cacheKey, &histories); err == nil {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Str("relative", relative).
			Msg("Family history by relative retrieved from cache")
		return histories, nil
	}

	// Fetch from database
	histories, err = s.familyHistoryRepo.GetFamilyHistoryByRelative(ctx, patientID, relative)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", patientID.String()).
			Str("relative", relative).
			Msg("Failed to get family history by relative")
		return nil, domain.NewAppError(err, "Failed to get family history by relative", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, histories, 60*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache family history by relative")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Str("relative", relative).
		Int("count", len(histories)).
		Msg("Family history by relative retrieved successfully")

	return histories, nil
}

// UpdateFamilyHistory updates a family history record
func (s *familyHistoryService) UpdateFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("family_history_id", history.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update family history completed")
	}()

	// Validate input
	if err := s.validateFamilyHistory(history); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing family history for the patient to verify ownership
	allHistories, err := s.familyHistoryRepo.GetPatientFamilyHistory(ctx, history.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", history.PatientID.String()).Msg("Failed to get patient family history")
		return domain.NewAppError(err, "Failed to get patient family history", 500)
	}

	// Find the family history
	var found bool
	for _, existing := range allHistories {
		if existing.ID == history.ID {
			found = true
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("family_history_id", history.ID.String()).
			Str("patient_id", history.PatientID.String()).
			Msg("Family history not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Family history not found for this patient", 404)
	}

	// Update family history
	if err := s.familyHistoryRepo.UpdateFamilyHistory(ctx, history); err != nil {
		s.logger.Error().Err(err).
			Str("family_history_id", history.ID.String()).
			Str("patient_id", history.PatientID.String()).
			Msg("Failed to update family history")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Family history not found", 404)
		}
		return domain.NewAppError(err, "Failed to update family history", 500)
	}

	// Invalidate cache for both all histories and relative-specific
	s.invalidateFamilyHistoryCache(ctx, history.PatientID)

	s.logger.Info().
		Str("family_history_id", history.ID.String()).
		Str("patient_id", history.PatientID.String()).
		Msg("Family history updated successfully")

	return nil
}

// DeleteFamilyHistory deletes a family history record
func (s *familyHistoryService) DeleteFamilyHistory(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("family_history_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete family history completed")
	}()

	// Delete family history
	if err := s.familyHistoryRepo.DeleteFamilyHistory(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("family_history_id", id.String()).Msg("Failed to delete family history")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Family history not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete family history", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID.
	// In a production system, you would add a GetFamilyHistoryByID method to the repository.

	s.logger.Info().Str("family_history_id", id.String()).Msg("Family history deleted successfully")
	return nil
}

// Validate family history
func (s *familyHistoryService) validateFamilyHistory(history patients.PatientFamilyHistory) error {
	if history.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(history.Relative) == "" {
		return fmt.Errorf("relative is required")
	}
	if strings.TrimSpace(history.ConditionName) == "" {
		return fmt.Errorf("condition name is required")
	}

	// Validate age at diagnosis
	if history.RelativeAgeAtDiagnosis != nil && *history.RelativeAgeAtDiagnosis < 0 {
		return fmt.Errorf("relative age at diagnosis cannot be negative")
	}

	// Validate age at death
	if history.AgeAtDeath != nil && *history.AgeAtDeath < 0 {
		return fmt.Errorf("age at death cannot be negative")
	}

	// Validate isAlive if provided
	if history.IsAlive != nil {
		if *history.IsAlive {
			// If alive, cause of death should be nil
			if history.CauseOfDeath != nil && strings.TrimSpace(*history.CauseOfDeath) != "" {
				return fmt.Errorf("cause of death should not be provided for living relative")
			}
			if history.AgeAtDeath != nil {
				return fmt.Errorf("age at death should not be provided for living relative")
			}
		} else {
			// If not alive, cause of death is required
			if history.CauseOfDeath == nil || strings.TrimSpace(*history.CauseOfDeath) == "" {
				return fmt.Errorf("cause of death is required for deceased relative")
			}
		}
	}

	return nil
}

// Helper methods
func (s *familyHistoryService) invalidateFamilyHistoryCache(ctx context.Context, patientID uuid.UUID) {
	// Get all relatives to invalidate their specific caches
	histories, err := s.familyHistoryRepo.GetPatientFamilyHistory(ctx, patientID)
	if err != nil {
		s.logger.Warn().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get family histories for cache invalidation")
		return
	}

	// Collect unique relatives
	relatives := make(map[string]bool)
	for _, history := range histories {
		relatives[history.Relative] = true
	}

	// Invalidate all histories cache
	cacheKeys := []string{
		fmt.Sprintf("family_history:all:%s", patientID.String()),
	}

	// Invalidate relative-specific caches
	for relative := range relatives {
		cacheKeys = append(cacheKeys, fmt.Sprintf("family_history:relative:%s:%s", patientID.String(), relative))
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate family history cache")
		}
	}
}
