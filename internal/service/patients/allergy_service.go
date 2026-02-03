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

type allergyService struct {
	allergyRepo repository.PatientAllergyRepository
	patientRepo repository.PatientProfileRepository
	cache       cache.Service
	logger      *zerolog.Logger
}

// NewAllergyService creates a new allergy service
func NewAllergyService(
	allergyRepo repository.PatientAllergyRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.AllergyService {
	return &allergyService{
		allergyRepo: allergyRepo,
		patientRepo: patientRepo,
		cache:       cache,
		logger:      logger,
	}
}

// AddPatientAllergy adds a new allergy for a patient
func (s *allergyService) AddPatientAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", allergy.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add patient allergy completed")
	}()

	// Validate input
	if err := s.validatePatientAllergy(allergy); err != nil {
		return patients.PatientAllergy{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, allergy.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", allergy.PatientID.String()).Msg("Patient not found")
			return patients.PatientAllergy{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", allergy.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientAllergy{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Set timestamps
	now := time.Now()
	allergy.ID = uuid.New()
	allergy.CreatedAt = now
	allergy.UpdatedAt = now

	// Set default status if not provided
	if allergy.Status == "" {
		allergy.Status = "active"
	}

	// Add allergy
	created, err := s.allergyRepo.AddPatientAllergy(ctx, allergy)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", allergy.PatientID.String()).
			Str("allergy_name", allergy.AllergyName).
			Msg("Failed to add patient allergy")
		return patients.PatientAllergy{}, domain.NewAppError(err, "Failed to add patient allergy", 500)
	}

	// Invalidate cache
	s.invalidateAllergyCache(ctx, allergy.PatientID)

	s.logger.Info().
		Str("allergy_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("allergy_name", created.AllergyName).
		Str("severity", created.Severity).
		Msg("Patient allergy added successfully")

	return created, nil
}

// GetPatientAllergies retrieves all allergies for a patient
func (s *allergyService) GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient allergies completed")
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
	cacheKey := fmt.Sprintf("allergies:all:%s", patientID.String())
	var allergies []patients.PatientAllergy
	if err := s.cache.Get(ctx, cacheKey, &allergies); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient allergies retrieved from cache")
		return allergies, nil
	}

	// Fetch from database
	allergies, err = s.allergyRepo.GetPatientAllergies(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient allergies")
		return nil, domain.NewAppError(err, "Failed to get patient allergies", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, allergies, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient allergies")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(allergies)).
		Msg("Patient allergies retrieved successfully")

	return allergies, nil
}

// GetActivePatientAllergies retrieves active allergies for a patient
func (s *allergyService) GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get active patient allergies completed")
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
	cacheKey := fmt.Sprintf("allergies:active:%s", patientID.String())
	var allergies []patients.PatientAllergy
	if err := s.cache.Get(ctx, cacheKey, &allergies); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Active patient allergies retrieved from cache")
		return allergies, nil
	}

	// Fetch from database
	allergies, err = s.allergyRepo.GetActivePatientAllergies(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get active patient allergies")
		return nil, domain.NewAppError(err, "Failed to get active patient allergies", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, allergies, 15*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache active patient allergies")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(allergies)).
		Msg("Active patient allergies retrieved successfully")

	return allergies, nil
}

// UpdatePatientAllergy updates an allergy record
func (s *allergyService) UpdatePatientAllergy(ctx context.Context, allergy patients.PatientAllergy) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("allergy_id", allergy.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient allergy completed")
	}()

	// Validate input
	if err := s.validatePatientAllergy(allergy); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing allergies for the patient to verify ownership
	allAllergies, err := s.allergyRepo.GetPatientAllergies(ctx, allergy.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", allergy.PatientID.String()).Msg("Failed to get patient allergies")
		return domain.NewAppError(err, "Failed to get patient allergies", 500)
	}

	// Find the allergy
	var found bool
	for _, existing := range allAllergies {
		if existing.ID == allergy.ID {
			found = true
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("allergy_id", allergy.ID.String()).
			Str("patient_id", allergy.PatientID.String()).
			Msg("Allergy not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Allergy not found for this patient", 404)
	}

	// Update timestamps
	allergy.UpdatedAt = time.Now()

	// Update allergy
	if err := s.allergyRepo.UpdatePatientAllergy(ctx, allergy); err != nil {
		s.logger.Error().Err(err).
			Str("allergy_id", allergy.ID.String()).
			Str("patient_id", allergy.PatientID.String()).
			Msg("Failed to update patient allergy")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Allergy not found", 404)
		}
		return domain.NewAppError(err, "Failed to update patient allergy", 500)
	}

	// Invalidate cache
	s.invalidateAllergyCache(ctx, allergy.PatientID)

	s.logger.Info().
		Str("allergy_id", allergy.ID.String()).
		Str("patient_id", allergy.PatientID.String()).
		Msg("Patient allergy updated successfully")

	return nil
}

// DeletePatientAllergy deletes an allergy record
func (s *allergyService) DeletePatientAllergy(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("allergy_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient allergy completed")
	}()

	// Delete allergy
	if err := s.allergyRepo.DeletePatientAllergy(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("allergy_id", id.String()).Msg("Failed to delete patient allergy")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Allergy not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete patient allergy", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID.
	// In a production system, you would add a GetAllergyByID method.

	s.logger.Info().Str("allergy_id", id.String()).Msg("Patient allergy deleted successfully")
	return nil
}

// Validate patient allergy
func (s *allergyService) validatePatientAllergy(allergy patients.PatientAllergy) error {
	if allergy.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(allergy.AllergyName) == "" {
		return fmt.Errorf("allergy name is required")
	}
	if strings.TrimSpace(allergy.Severity) == "" {
		return fmt.Errorf("severity is required")
	}
	if !s.isValidSeverity(allergy.Severity) {
		return fmt.Errorf("invalid severity: %s", allergy.Severity)
	}
	if allergy.Status != "" && !s.isValidAllergyStatus(allergy.Status) {
		return fmt.Errorf("invalid allergy status: %s", allergy.Status)
	}

	// Validate dates
	if allergy.FirstIdentifiedDate != nil && allergy.FirstIdentifiedDate.After(time.Now()) {
		return fmt.Errorf("first identified date cannot be in the future")
	}

	if allergy.LastOccurrenceDate != nil && allergy.LastOccurrenceDate.After(time.Now()) {
		return fmt.Errorf("last occurrence date cannot be in the future")
	}

	if allergy.LastOccurrenceDate != nil && allergy.FirstIdentifiedDate != nil &&
		allergy.LastOccurrenceDate.Before(*allergy.FirstIdentifiedDate) {
		return fmt.Errorf("last occurrence date cannot be before first identified date")
	}

	return nil
}

// Helper methods
func (s *allergyService) invalidateAllergyCache(ctx context.Context, patientID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("allergies:all:%s", patientID.String()),
		fmt.Sprintf("allergies:active:%s", patientID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate allergy cache")
		}
	}
}

func (s *allergyService) isValidSeverity(severity string) bool {
	validSeverities := []string{"mild", "moderate", "severe", "life-threatening"}
	for _, validSeverity := range validSeverities {
		if strings.EqualFold(severity, validSeverity) {
			return true
		}
	}
	return false
}

func (s *allergyService) isValidAllergyStatus(status string) bool {
	validStatuses := []string{"active", "resolved", "outgrown", "inactive"}
	for _, validStatus := range validStatuses {
		if strings.EqualFold(status, validStatus) {
			return true
		}
	}
	return false
}
