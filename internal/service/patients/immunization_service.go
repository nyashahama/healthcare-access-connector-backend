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

type immunizationService struct {
	immunizationRepo repository.PatientImmunizationRepository
	patientRepo      repository.PatientProfileRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

func (s *immunizationService) cacheAvailable() bool {
	return s != nil && s.cache != nil && s.cache.IsAvailable()
}

// NewImmunizationService creates a new immunization service
func NewImmunizationService(
	immunizationRepo repository.PatientImmunizationRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ImmunizationService {
	return &immunizationService{
		immunizationRepo: immunizationRepo,
		patientRepo:      patientRepo,
		cache:            cache,
		logger:           logger,
	}
}

// AddPatientImmunization adds a new immunization for a patient
func (s *immunizationService) AddPatientImmunization(ctx context.Context, immunization patients.PatientImmunization) (patients.PatientImmunization, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", immunization.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add patient immunization completed")
	}()

	// Validate input
	if err := s.validatePatientImmunization(immunization); err != nil {
		return patients.PatientImmunization{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, immunization.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", immunization.PatientID.String()).Msg("Patient not found")
			return patients.PatientImmunization{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", immunization.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientImmunization{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Set timestamps
	now := time.Now()
	immunization.ID = uuid.New()
	immunization.CreatedAt = now
	immunization.UpdatedAt = now

	// Ensure dose numbers are valid
	if immunization.DoseNumber != nil && immunization.TotalDoses != nil {
		if *immunization.DoseNumber > *immunization.TotalDoses {
			return patients.PatientImmunization{}, domain.NewAppError(domain.ErrValidation, "Dose number cannot exceed total doses", 400)
		}
	}

	// Add immunization
	created, err := s.immunizationRepo.AddPatientImmunization(ctx, immunization)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", immunization.PatientID.String()).
			Str("vaccine_name", immunization.VaccineName).
			Msg("Failed to add patient immunization")
		return patients.PatientImmunization{}, domain.NewAppError(err, "Failed to add patient immunization", 500)
	}

	// Invalidate cache
	s.invalidateImmunizationCache(ctx, immunization.PatientID)

	s.logger.Info().
		Str("immunization_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("vaccine_name", created.VaccineName).
		Msg("Patient immunization added successfully")

	return created, nil
}

// GetPatientImmunizations retrieves all immunizations for a patient
func (s *immunizationService) GetPatientImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient immunizations completed")
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
	cacheKey := fmt.Sprintf("immunizations:all:%s", patientID.String())
	var immunizations []patients.PatientImmunization
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &immunizations); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient immunizations retrieved from cache")
			return immunizations, nil
		}
	}

	// Fetch from database
	immunizations, err = s.immunizationRepo.GetPatientImmunizations(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient immunizations")
		return nil, domain.NewAppError(err, "Failed to get patient immunizations", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, immunizations, 30*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache patient immunizations")
		}
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(immunizations)).
		Msg("Patient immunizations retrieved successfully")

	return immunizations, nil
}

// GetUpcomingImmunizations retrieves upcoming immunizations for a patient
func (s *immunizationService) GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get upcoming immunizations completed")
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
	cacheKey := fmt.Sprintf("immunizations:upcoming:%s", patientID.String())
	var immunizations []patients.PatientImmunization
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &immunizations); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Upcoming immunizations retrieved from cache")
			return immunizations, nil
		}
	}

	// Fetch from database
	immunizations, err = s.immunizationRepo.GetUpcomingImmunizations(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get upcoming immunizations")
		return nil, domain.NewAppError(err, "Failed to get upcoming immunizations", 500)
	}

	// Filter to only future dates
	var futureImmunizations []patients.PatientImmunization
	now := time.Now()
	for _, immunization := range immunizations {
		if immunization.NextDueDate != nil && immunization.NextDueDate.After(now) {
			futureImmunizations = append(futureImmunizations, immunization)
		}
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, futureImmunizations, 24*time.Hour); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache upcoming immunizations")
		}
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(futureImmunizations)).
		Msg("Upcoming immunizations retrieved successfully")

	return futureImmunizations, nil
}

// UpdatePatientImmunization updates an immunization record
func (s *immunizationService) UpdatePatientImmunization(ctx context.Context, immunization patients.PatientImmunization) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("immunization_id", immunization.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient immunization completed")
	}()

	// Validate input
	if err := s.validatePatientImmunization(immunization); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing immunizations for the patient to verify ownership
	allImmunizations, err := s.immunizationRepo.GetPatientImmunizations(ctx, immunization.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", immunization.PatientID.String()).Msg("Failed to get patient immunizations")
		return domain.NewAppError(err, "Failed to get patient immunizations", 500)
	}

	// Find the immunization
	var found bool
	for _, existing := range allImmunizations {
		if existing.ID == immunization.ID {
			found = true
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("immunization_id", immunization.ID.String()).
			Str("patient_id", immunization.PatientID.String()).
			Msg("Immunization not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Immunization not found for this patient", 404)
	}

	// Update timestamps
	immunization.UpdatedAt = time.Now()

	// Update immunization
	if err := s.immunizationRepo.UpdatePatientImmunization(ctx, immunization); err != nil {
		s.logger.Error().Err(err).
			Str("immunization_id", immunization.ID.String()).
			Str("patient_id", immunization.PatientID.String()).
			Msg("Failed to update patient immunization")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Immunization not found", 404)
		}
		return domain.NewAppError(err, "Failed to update patient immunization", 500)
	}

	// Invalidate cache
	s.invalidateImmunizationCache(ctx, immunization.PatientID)

	s.logger.Info().
		Str("immunization_id", immunization.ID.String()).
		Str("patient_id", immunization.PatientID.String()).
		Msg("Patient immunization updated successfully")

	return nil
}

// DeletePatientImmunization deletes an immunization record
func (s *immunizationService) DeletePatientImmunization(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("immunization_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient immunization completed")
	}()

	// Delete immunization
	if err := s.immunizationRepo.DeletePatientImmunization(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("immunization_id", id.String()).Msg("Failed to delete patient immunization")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Immunization not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete patient immunization", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID.
	// In a production system, you would add a GetImmunizationByID method to the repository.

	s.logger.Info().Str("immunization_id", id.String()).Msg("Patient immunization deleted successfully")
	return nil
}

// Validate patient immunization
func (s *immunizationService) validatePatientImmunization(immunization patients.PatientImmunization) error {
	if immunization.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(immunization.VaccineName) == "" {
		return fmt.Errorf("vaccine name is required")
	}
	if immunization.AdministrationDate.IsZero() {
		return fmt.Errorf("administration date is required")
	}
	if immunization.AdministrationDate.After(time.Now()) {
		return fmt.Errorf("administration date cannot be in the future")
	}
	if immunization.NextDueDate != nil && immunization.NextDueDate.Before(immunization.AdministrationDate) {
		return fmt.Errorf("next due date cannot be before administration date")
	}

	// Validate dose numbers
	if immunization.DoseNumber != nil && *immunization.DoseNumber <= 0 {
		return fmt.Errorf("dose number must be positive")
	}
	if immunization.TotalDoses != nil && *immunization.TotalDoses <= 0 {
		return fmt.Errorf("total doses must be positive")
	}
	if immunization.DoseNumber != nil && immunization.TotalDoses != nil && *immunization.DoseNumber > *immunization.TotalDoses {
		return fmt.Errorf("dose number cannot exceed total doses")
	}

	return nil
}

// Helper methods
func (s *immunizationService) invalidateImmunizationCache(ctx context.Context, patientID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("immunizations:all:%s", patientID.String()),
		fmt.Sprintf("immunizations:upcoming:%s", patientID.String()),
	}

	for _, key := range cacheKeys {
		if s.cacheAvailable() {
			if err := s.cache.Delete(ctx, key); err != nil {
				s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate immunization cache")
			}
		}
	}
}
