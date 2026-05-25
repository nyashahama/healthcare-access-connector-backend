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

type dependentService struct {
	dependentRepo repository.PatientDependentRepository
	patientRepo   repository.PatientProfileRepository
	cache         cache.Service
	logger        *zerolog.Logger
}

func (s *dependentService) cacheAvailable() bool {
	return s != nil && s.cache != nil && s.cache.IsAvailable()
}

// NewDependentService creates a new dependent service
func NewDependentService(
	dependentRepo repository.PatientDependentRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.DependentService {
	return &dependentService{
		dependentRepo: dependentRepo,
		patientRepo:   patientRepo,
		cache:         cache,
		logger:        logger,
	}
}

// AddPatientDependent adds a new dependent for a patient
func (s *dependentService) AddPatientDependent(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", dependent.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add patient dependent completed")
	}()

	// Validate input
	if err := s.validatePatientDependent(dependent); err != nil {
		return patients.PatientDependent{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, dependent.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", dependent.PatientID.String()).Msg("Patient not found")
			return patients.PatientDependent{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", dependent.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientDependent{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Check dependent age based on relationship
	if err := s.validateDependentAge(dependent); err != nil {
		return patients.PatientDependent{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Set timestamps
	now := time.Now()
	dependent.ID = uuid.New()
	dependent.CreatedAt = now
	dependent.UpdatedAt = now

	// Add dependent
	created, err := s.dependentRepo.AddPatientDependent(ctx, dependent)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", dependent.PatientID.String()).
			Str("dependent_name", fmt.Sprintf("%s %s", dependent.FirstName, dependent.LastName)).
			Msg("Failed to add patient dependent")
		return patients.PatientDependent{}, domain.NewAppError(err, "Failed to add patient dependent", 500)
	}

	// Invalidate cache
	s.invalidateDependentCache(ctx, dependent.PatientID)

	s.logger.Info().
		Str("dependent_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("name", fmt.Sprintf("%s %s", created.FirstName, created.LastName)).
		Str("relationship", created.Relationship).
		Msg("Patient dependent added successfully")

	return created, nil
}

// GetPatientDependents retrieves all dependents for a patient
func (s *dependentService) GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient dependents completed")
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
	cacheKey := fmt.Sprintf("dependents:all:%s", patientID.String())
	var dependents []patients.PatientDependent
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &dependents); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient dependents retrieved from cache")
			return dependents, nil
		}
	}

	// Fetch from database
	dependents, err = s.dependentRepo.GetPatientDependents(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient dependents")
		return nil, domain.NewAppError(err, "Failed to get patient dependents", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, dependents, 30*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache patient dependents")
		}
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(dependents)).
		Msg("Patient dependents retrieved successfully")

	return dependents, nil
}

// GetDependentChildren retrieves child dependents for a patient
func (s *dependentService) GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get dependent children completed")
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
	cacheKey := fmt.Sprintf("dependents:children:%s", patientID.String())
	var dependents []patients.PatientDependent
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &dependents); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Dependent children retrieved from cache")
			return dependents, nil
		}
	}

	// Fetch from database
	dependents, err = s.dependentRepo.GetDependentChildren(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get dependent children")
		return nil, domain.NewAppError(err, "Failed to get dependent children", 500)
	}

	// Filter for children (age-based filter)
	var children []patients.PatientDependent
	now := time.Now()
	for _, dependent := range dependents {
		age := s.calculateAge(dependent.DateOfBirth, now)
		if age < 18 {
			children = append(children, dependent)
		}
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, children, 30*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache dependent children")
		}
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(children)).
		Msg("Dependent children retrieved successfully")

	return children, nil
}

// UpdatePatientDependent updates a dependent record
func (s *dependentService) UpdatePatientDependent(ctx context.Context, dependent patients.PatientDependent) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("dependent_id", dependent.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient dependent completed")
	}()

	// Validate input
	if err := s.validatePatientDependent(dependent); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing dependents for the patient to verify ownership
	allDependents, err := s.dependentRepo.GetPatientDependents(ctx, dependent.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", dependent.PatientID.String()).Msg("Failed to get patient dependents")
		return domain.NewAppError(err, "Failed to get patient dependents", 500)
	}

	// Find the dependent
	var found bool
	for _, existing := range allDependents {
		if existing.ID == dependent.ID {
			found = true
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("dependent_id", dependent.ID.String()).
			Str("patient_id", dependent.PatientID.String()).
			Msg("Dependent not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Dependent not found for this patient", 404)
	}

	// Update timestamps
	dependent.UpdatedAt = time.Now()

	// Update dependent
	if err := s.dependentRepo.UpdatePatientDependent(ctx, dependent); err != nil {
		s.logger.Error().Err(err).
			Str("dependent_id", dependent.ID.String()).
			Str("patient_id", dependent.PatientID.String()).
			Msg("Failed to update patient dependent")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Dependent not found", 404)
		}
		return domain.NewAppError(err, "Failed to update patient dependent", 500)
	}

	// Invalidate cache
	s.invalidateDependentCache(ctx, dependent.PatientID)

	s.logger.Info().
		Str("dependent_id", dependent.ID.String()).
		Str("patient_id", dependent.PatientID.String()).
		Msg("Patient dependent updated successfully")

	return nil
}

// DeletePatientDependent deletes a dependent record
func (s *dependentService) DeletePatientDependent(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("dependent_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient dependent completed")
	}()

	// Delete dependent
	if err := s.dependentRepo.DeletePatientDependent(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("dependent_id", id.String()).Msg("Failed to delete patient dependent")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Dependent not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete patient dependent", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID.
	// In a production system, you would add a GetDependentByID method to the repository.

	s.logger.Info().Str("dependent_id", id.String()).Msg("Patient dependent deleted successfully")
	return nil
}

// Validate patient dependent
func (s *dependentService) validatePatientDependent(dependent patients.PatientDependent) error {
	if dependent.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(dependent.FirstName) == "" {
		return fmt.Errorf("first name is required")
	}
	if strings.TrimSpace(dependent.LastName) == "" {
		return fmt.Errorf("last name is required")
	}
	if dependent.DateOfBirth.IsZero() {
		return fmt.Errorf("date of birth is required")
	}
	if dependent.DateOfBirth.After(time.Now()) {
		return fmt.Errorf("date of birth cannot be in the future")
	}
	if strings.TrimSpace(dependent.Relationship) == "" {
		return fmt.Errorf("relationship is required")
	}

	// Validate gender if provided
	if dependent.Gender != nil && !s.isValidGender(*dependent.Gender) {
		return fmt.Errorf("invalid gender: %s", *dependent.Gender)
	}

	// Validate numeric values
	if dependent.BirthWeightKg != nil && *dependent.BirthWeightKg <= 0 {
		return fmt.Errorf("birth weight must be positive")
	}

	if dependent.BirthHeightCm != nil && *dependent.BirthHeightCm <= 0 {
		return fmt.Errorf("birth height must be positive")
	}

	return nil
}

// Validate dependent age based on relationship
func (s *dependentService) validateDependentAge(dependent patients.PatientDependent) error {
	age := s.calculateAge(dependent.DateOfBirth, time.Now())

	switch strings.ToLower(dependent.Relationship) {
	case "child", "son", "daughter":
		if age >= 18 {
			return fmt.Errorf("child dependents must be under 18 years old")
		}
	case "spouse", "partner":
		if age < 18 {
			return fmt.Errorf("spouse/partner dependents must be at least 18 years old")
		}
	case "parent", "mother", "father":
		// Parents are typically older, but no strict age validation
		if age < 18 {
			return fmt.Errorf("parent dependents must be at least 18 years old")
		}
	}

	return nil
}

// Helper methods
func (s *dependentService) invalidateDependentCache(ctx context.Context, patientID uuid.UUID) {
	if !s.cacheAvailable() {
		return
	}

	cacheKeys := []string{
		fmt.Sprintf("dependents:all:%s", patientID.String()),
		fmt.Sprintf("dependents:children:%s", patientID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate dependent cache")
		}
	}
}

func (s *dependentService) calculateAge(birthDate, referenceDate time.Time) int {
	years := referenceDate.Year() - birthDate.Year()

	// Adjust if birthday hasn't occurred yet this year
	if referenceDate.Month() < birthDate.Month() ||
		(referenceDate.Month() == birthDate.Month() && referenceDate.Day() < birthDate.Day()) {
		years--
	}

	return years
}

func (s *dependentService) isValidGender(gender string) bool {
	validGenders := []string{"male", "female", "other", "prefer not to say"}
	for _, validGender := range validGenders {
		if strings.EqualFold(gender, validGender) {
			return true
		}
	}
	return false
}
