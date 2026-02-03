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

type surgeryService struct {
	surgeryRepo repository.PatientSurgeryRepository
	patientRepo repository.PatientProfileRepository
	cache       cache.Service
	logger      *zerolog.Logger
}

// NewSurgeryService creates a new surgery service
func NewSurgeryService(
	surgeryRepo repository.PatientSurgeryRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.SurgeryService {
	return &surgeryService{
		surgeryRepo: surgeryRepo,
		patientRepo: patientRepo,
		cache:       cache,
		logger:      logger,
	}
}

// AddPatientSurgery adds a new surgery record for a patient
func (s *surgeryService) AddPatientSurgery(ctx context.Context, surgery patients.PatientSurgery) (patients.PatientSurgery, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", surgery.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add patient surgery completed")
	}()

	// Validate input
	if err := s.validatePatientSurgery(surgery); err != nil {
		return patients.PatientSurgery{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, surgery.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", surgery.PatientID.String()).Msg("Patient not found")
			return patients.PatientSurgery{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", surgery.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientSurgery{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Set timestamps
	now := time.Now()
	surgery.ID = uuid.New()
	surgery.CreatedAt = now
	surgery.UpdatedAt = now

	// Add surgery record
	created, err := s.surgeryRepo.AddPatientSurgery(ctx, surgery)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", surgery.PatientID.String()).
			Str("procedure_name", surgery.ProcedureName).
			Msg("Failed to add patient surgery")
		return patients.PatientSurgery{}, domain.NewAppError(err, "Failed to add patient surgery", 500)
	}

	// Invalidate cache
	s.invalidateSurgeryCache(ctx, surgery.PatientID)

	s.logger.Info().
		Str("surgery_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("procedure_name", created.ProcedureName).
		Msg("Patient surgery added successfully")

	return created, nil
}

// GetPatientSurgeries retrieves all surgeries for a patient
func (s *surgeryService) GetPatientSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient surgeries completed")
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
	cacheKey := fmt.Sprintf("patient:surgeries:%s", patientID.String())
	var surgeries []patients.PatientSurgery
	if err := s.cache.Get(ctx, cacheKey, &surgeries); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient surgeries retrieved from cache")
		return surgeries, nil
	}

	// Fetch from database
	surgeries, err = s.surgeryRepo.GetPatientSurgeries(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient surgeries")
		return nil, domain.NewAppError(err, "Failed to get patient surgeries", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, surgeries, 15*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient surgeries")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(surgeries)).
		Msg("Patient surgeries retrieved successfully")

	return surgeries, nil
}

// GetRecentSurgeries retrieves recent surgeries for a patient (simplified view)
func (s *surgeryService) GetRecentSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get recent surgeries completed")
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
	cacheKey := fmt.Sprintf("patient:recent_surgeries:%s", patientID.String())
	var surgeries []patients.PatientSurgery
	if err := s.cache.Get(ctx, cacheKey, &surgeries); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Recent surgeries retrieved from cache")
		return surgeries, nil
	}

	// Fetch from database
	surgeries, err = s.surgeryRepo.GetRecentSurgeries(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get recent surgeries")
		return nil, domain.NewAppError(err, "Failed to get recent surgeries", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, surgeries, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache recent surgeries")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(surgeries)).
		Msg("Recent surgeries retrieved successfully")

	return surgeries, nil
}

// UpdatePatientSurgery updates an existing surgery record
func (s *surgeryService) UpdatePatientSurgery(ctx context.Context, surgery patients.PatientSurgery) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("surgery_id", surgery.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient surgery completed")
	}()

	// Validate input
	if err := s.validatePatientSurgery(surgery); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing surgery to verify patient ownership and get patient ID for cache invalidation
	existingSurgeries, err := s.surgeryRepo.GetPatientSurgeries(ctx, surgery.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", surgery.PatientID.String()).Msg("Failed to get patient surgeries")
		return domain.NewAppError(err, "Failed to get patient surgeries", 500)
	}

	var found bool
	for _, existing := range existingSurgeries {
		if existing.ID == surgery.ID {
			found = true
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("surgery_id", surgery.ID.String()).
			Str("patient_id", surgery.PatientID.String()).
			Msg("Surgery not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Surgery not found for this patient", 404)
	}

	// Update timestamps
	surgery.UpdatedAt = time.Now()

	// Update surgery record
	if err := s.surgeryRepo.UpdatePatientSurgery(ctx, surgery); err != nil {
		s.logger.Error().Err(err).
			Str("surgery_id", surgery.ID.String()).
			Str("patient_id", surgery.PatientID.String()).
			Msg("Failed to update patient surgery")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Surgery not found", 404)
		}
		return domain.NewAppError(err, "Failed to update patient surgery", 500)
	}

	// Invalidate cache
	s.invalidateSurgeryCache(ctx, surgery.PatientID)

	s.logger.Info().
		Str("surgery_id", surgery.ID.String()).
		Str("patient_id", surgery.PatientID.String()).
		Msg("Patient surgery updated successfully")

	return nil
}

// DeletePatientSurgery deletes a surgery record
func (s *surgeryService) DeletePatientSurgery(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("surgery_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient surgery completed")
	}()

	// We need to get the surgery first to know the patient ID for cache invalidation
	// Since we don't have a GetSurgeryByID method, we need to be creative.
	// For now, we'll delete directly and rely on the repository to handle the foreign key.
	// In a real scenario, you might want to add a GetSurgeryByID method to the repository.

	// For cache invalidation, we'll need to know the patient ID.
	// This is a limitation of the current repository design.
	// For now, we'll skip cache invalidation for delete (which is not ideal).
	// Alternatively, we could pass the patient ID as a parameter, but the interface doesn't allow it.

	// Delete surgery record
	if err := s.surgeryRepo.DeletePatientSurgery(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("surgery_id", id.String()).Msg("Failed to delete patient surgery")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Surgery not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete patient surgery", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID.
	// In a production system, you would either:
	// 1. Add a GetSurgeryByID method to the repository
	// 2. Pass patient ID as a parameter to DeletePatientSurgery
	// 3. Use a different cache strategy

	s.logger.Info().Str("surgery_id", id.String()).Msg("Patient surgery deleted successfully")
	return nil
}

// Validate patient surgery
func (s *surgeryService) validatePatientSurgery(surgery patients.PatientSurgery) error {
	if surgery.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if surgery.ProcedureName == "" {
		return fmt.Errorf("procedure name is required")
	}
	if surgery.ProcedureDate.IsZero() {
		return fmt.Errorf("procedure date is required")
	}
	if surgery.ProcedureDate.After(time.Now()) {
		return fmt.Errorf("procedure date cannot be in the future")
	}
	return nil
}

// Helper methods
func (s *surgeryService) invalidateSurgeryCache(ctx context.Context, patientID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("patient:surgeries:%s", patientID.String()),
		fmt.Sprintf("patient:recent_surgeries:%s", patientID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate surgery cache")
		}
	}
}
