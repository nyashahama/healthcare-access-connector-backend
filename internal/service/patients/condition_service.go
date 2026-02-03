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

type conditionService struct {
	conditionRepo repository.PatientConditionRepository
	patientRepo   repository.PatientProfileRepository
	cache         cache.Service
	logger        *zerolog.Logger
}

// NewConditionService creates a new condition service
func NewConditionService(
	conditionRepo repository.PatientConditionRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ConditionService {
	return &conditionService{
		conditionRepo: conditionRepo,
		patientRepo:   patientRepo,
		cache:         cache,
		logger:        logger,
	}
}

// AddPatientCondition adds a new condition for a patient
func (s *conditionService) AddPatientCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", condition.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add patient condition completed")
	}()

	// Validate input
	if err := s.validatePatientCondition(condition); err != nil {
		return patients.PatientCondition{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, condition.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", condition.PatientID.String()).Msg("Patient not found")
			return patients.PatientCondition{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", condition.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientCondition{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Set timestamps
	now := time.Now()
	condition.ID = uuid.New()
	condition.CreatedAt = now
	condition.UpdatedAt = now

	// Set default status if not provided
	if condition.Status == "" {
		condition.Status = "active"
	}

	// Add condition
	created, err := s.conditionRepo.AddPatientCondition(ctx, condition)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", condition.PatientID.String()).
			Str("condition_name", condition.ConditionName).
			Msg("Failed to add patient condition")
		return patients.PatientCondition{}, domain.NewAppError(err, "Failed to add patient condition", 500)
	}

	// Invalidate cache
	s.invalidateConditionCache(ctx, condition.PatientID, &condition.Status)

	s.logger.Info().
		Str("condition_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("condition_name", created.ConditionName).
		Str("status", created.Status).
		Msg("Patient condition added successfully")

	return created, nil
}

// GetPatientConditions retrieves all conditions for a patient, optionally filtered by status
func (s *conditionService) GetPatientConditions(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientCondition, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient conditions completed")
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

	// Generate cache key
	cacheKey := s.generateConditionCacheKey(patientID, status)

	// Try cache first
	var conditions []patients.PatientCondition
	if err := s.cache.Get(ctx, cacheKey, &conditions); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient conditions retrieved from cache")
		return conditions, nil
	}

	// Fetch from database
	conditions, err = s.conditionRepo.GetPatientConditions(ctx, patientID, status)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient conditions")
		return nil, domain.NewAppError(err, "Failed to get patient conditions", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, conditions, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient conditions")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(conditions)).
		Str("status", s.statusToString(status)).
		Msg("Patient conditions retrieved successfully")

	return conditions, nil
}

// GetActiveConditions retrieves active conditions for a patient
func (s *conditionService) GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get active conditions completed")
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
	cacheKey := fmt.Sprintf("conditions:active:%s", patientID.String())
	var conditions []patients.PatientCondition
	if err := s.cache.Get(ctx, cacheKey, &conditions); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Active conditions retrieved from cache")
		return conditions, nil
	}

	// Fetch from database
	conditions, err = s.conditionRepo.GetActiveConditions(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get active conditions")
		return nil, domain.NewAppError(err, "Failed to get active conditions", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, conditions, 15*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache active conditions")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(conditions)).
		Msg("Active conditions retrieved successfully")

	return conditions, nil
}

// UpdatePatientCondition updates a condition record
func (s *conditionService) UpdatePatientCondition(ctx context.Context, condition patients.PatientCondition) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("condition_id", condition.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient condition completed")
	}()

	// Validate input
	if err := s.validatePatientCondition(condition); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing conditions for the patient to verify ownership
	allConditions, err := s.conditionRepo.GetPatientConditions(ctx, condition.PatientID, nil)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", condition.PatientID.String()).Msg("Failed to get patient conditions")
		return domain.NewAppError(err, "Failed to get patient conditions", 500)
	}

	// Find the condition
	var found bool
	var oldStatus string
	for _, existing := range allConditions {
		if existing.ID == condition.ID {
			found = true
			oldStatus = existing.Status
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("condition_id", condition.ID.String()).
			Str("patient_id", condition.PatientID.String()).
			Msg("Condition not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Condition not found for this patient", 404)
	}

	// Update timestamps
	condition.UpdatedAt = time.Now()

	// Update condition
	if err := s.conditionRepo.UpdatePatientCondition(ctx, condition); err != nil {
		s.logger.Error().Err(err).
			Str("condition_id", condition.ID.String()).
			Str("patient_id", condition.PatientID.String()).
			Msg("Failed to update patient condition")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Condition not found", 404)
		}
		return domain.NewAppError(err, "Failed to update patient condition", 500)
	}

	// Invalidate cache for both old and new status
	s.invalidateConditionCache(ctx, condition.PatientID, &oldStatus)
	s.invalidateConditionCache(ctx, condition.PatientID, &condition.Status)

	s.logger.Info().
		Str("condition_id", condition.ID.String()).
		Str("patient_id", condition.PatientID.String()).
		Msg("Patient condition updated successfully")

	return nil
}

// DeletePatientCondition deletes a condition record
func (s *conditionService) DeletePatientCondition(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("condition_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient condition completed")
	}()

	// Delete condition
	if err := s.conditionRepo.DeletePatientCondition(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("condition_id", id.String()).Msg("Failed to delete patient condition")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Condition not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete patient condition", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID and status.
	// In a production system, you would add a GetConditionByID method.

	s.logger.Info().Str("condition_id", id.String()).Msg("Patient condition deleted successfully")
	return nil
}

// Validate patient condition
func (s *conditionService) validatePatientCondition(condition patients.PatientCondition) error {
	if condition.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(condition.ConditionName) == "" {
		return fmt.Errorf("condition name is required")
	}
	if condition.Status != "" && !s.isValidConditionStatus(condition.Status) {
		return fmt.Errorf("invalid condition status: %s", condition.Status)
	}

	// Validate dates
	if condition.DiagnosedDate != nil && condition.DiagnosedDate.After(time.Now()) {
		return fmt.Errorf("diagnosed date cannot be in the future")
	}

	if condition.LastFlareUp != nil && condition.LastFlareUp.After(time.Now()) {
		return fmt.Errorf("last flare-up date cannot be in the future")
	}

	if condition.NextCheckupDate != nil && condition.NextCheckupDate.Before(time.Now()) {
		return fmt.Errorf("next checkup date cannot be in the past")
	}

	// Validate severity if provided
	if condition.Severity != nil && !s.isValidSeverity(*condition.Severity) {
		return fmt.Errorf("invalid severity: %s", *condition.Severity)
	}

	return nil
}

// Helper methods
func (s *conditionService) invalidateConditionCache(ctx context.Context, patientID uuid.UUID, status *string) {
	cacheKeys := []string{
		fmt.Sprintf("conditions:all:%s", patientID.String()),
		fmt.Sprintf("conditions:active:%s", patientID.String()),
	}

	// Also invalidate status-specific cache
	if status != nil {
		cacheKeys = append(cacheKeys, fmt.Sprintf("conditions:%s:%s", *status, patientID.String()))
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate condition cache")
		}
	}
}

func (s *conditionService) generateConditionCacheKey(patientID uuid.UUID, status *string) string {
	if status != nil {
		return fmt.Sprintf("conditions:%s:%s", *status, patientID.String())
	}
	return fmt.Sprintf("conditions:all:%s", patientID.String())
}

func (s *conditionService) statusToString(status *string) string {
	if status == nil {
		return "all"
	}
	return *status
}

func (s *conditionService) isValidConditionStatus(status string) bool {
	validStatuses := []string{"active", "resolved", "chronic", "inactive", "remission"}
	for _, validStatus := range validStatuses {
		if strings.EqualFold(status, validStatus) {
			return true
		}
	}
	return false
}

func (s *conditionService) isValidSeverity(severity string) bool {
	validSeverities := []string{"mild", "moderate", "severe", "critical"}
	for _, validSeverity := range validSeverities {
		if strings.EqualFold(severity, validSeverity) {
			return true
		}
	}
	return false
}
