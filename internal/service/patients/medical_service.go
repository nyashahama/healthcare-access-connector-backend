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

type medicationService struct {
	medicationRepo repository.PatientMedicationRepository
	patientRepo    repository.PatientProfileRepository
	cache          cache.Service
	logger         *zerolog.Logger
}

// NewMedicationService creates a new medication service
func NewMedicationService(
	medicationRepo repository.PatientMedicationRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.MedicationService {
	return &medicationService{
		medicationRepo: medicationRepo,
		patientRepo:    patientRepo,
		cache:          cache,
		logger:         logger,
	}
}

// AddPatientMedication adds a new medication for a patient
func (s *medicationService) AddPatientMedication(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", medication.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Add patient medication completed")
	}()

	// Validate input
	if err := s.validatePatientMedication(medication); err != nil {
		return patients.PatientMedication{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, medication.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", medication.PatientID.String()).Msg("Patient not found")
			return patients.PatientMedication{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", medication.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientMedication{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Set timestamps
	now := time.Now()
	medication.ID = uuid.New()
	medication.CreatedAt = now
	medication.UpdatedAt = now

	// Set default status if not provided
	if medication.Status == "" {
		medication.Status = "active"
	}

	// Add medication
	created, err := s.medicationRepo.AddPatientMedication(ctx, medication)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", medication.PatientID.String()).
			Str("medication_name", medication.MedicationName).
			Msg("Failed to add patient medication")
		return patients.PatientMedication{}, domain.NewAppError(err, "Failed to add patient medication", 500)
	}

	// Invalidate cache
	s.invalidateMedicationCache(ctx, medication.PatientID, &medication.Status)

	s.logger.Info().
		Str("medication_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("medication_name", created.MedicationName).
		Str("status", created.Status).
		Msg("Patient medication added successfully")

	return created, nil
}

// GetPatientMedications retrieves all medications for a patient, optionally filtered by status
func (s *medicationService) GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient medications completed")
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
	cacheKey := s.generateMedicationCacheKey(patientID, status)

	// Try cache first
	var medications []patients.PatientMedication
	if err := s.cache.Get(ctx, cacheKey, &medications); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient medications retrieved from cache")
		return medications, nil
	}

	// Fetch from database
	medications, err = s.medicationRepo.GetPatientMedications(ctx, patientID, status)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient medications")
		return nil, domain.NewAppError(err, "Failed to get patient medications", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, medications, 15*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient medications")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(medications)).
		Str("status", s.statusToString(status)).
		Msg("Patient medications retrieved successfully")

	return medications, nil
}

// GetActiveMedications retrieves active medications for a patient
func (s *medicationService) GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get active medications completed")
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
	cacheKey := fmt.Sprintf("medications:active:%s", patientID.String())
	var medications []patients.PatientMedication
	if err := s.cache.Get(ctx, cacheKey, &medications); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Active medications retrieved from cache")
		return medications, nil
	}

	// Fetch from database
	medications, err = s.medicationRepo.GetActiveMedications(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get active medications")
		return nil, domain.NewAppError(err, "Failed to get active medications", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, medications, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache active medications")
	}

	s.logger.Debug().
		Str("patient_id", patientID.String()).
		Int("count", len(medications)).
		Msg("Active medications retrieved successfully")

	return medications, nil
}

// UpdatePatientMedication updates a medication record
func (s *medicationService) UpdatePatientMedication(ctx context.Context, medication patients.PatientMedication) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("medication_id", medication.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient medication completed")
	}()

	// Validate input
	if err := s.validatePatientMedication(medication); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing medications for the patient to verify ownership
	allMedications, err := s.medicationRepo.GetPatientMedications(ctx, medication.PatientID, nil)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", medication.PatientID.String()).Msg("Failed to get patient medications")
		return domain.NewAppError(err, "Failed to get patient medications", 500)
	}

	// Find the medication
	var found bool
	var oldStatus string
	for _, existing := range allMedications {
		if existing.ID == medication.ID {
			found = true
			oldStatus = existing.Status
			break
		}
	}

	if !found {
		s.logger.Debug().
			Str("medication_id", medication.ID.String()).
			Str("patient_id", medication.PatientID.String()).
			Msg("Medication not found for patient")
		return domain.NewAppError(domain.ErrNotFound, "Medication not found for this patient", 404)
	}

	// Update timestamps
	medication.UpdatedAt = time.Now()

	// Update medication
	if err := s.medicationRepo.UpdatePatientMedication(ctx, medication); err != nil {
		s.logger.Error().Err(err).
			Str("medication_id", medication.ID.String()).
			Str("patient_id", medication.PatientID.String()).
			Msg("Failed to update patient medication")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Medication not found", 404)
		}
		return domain.NewAppError(err, "Failed to update patient medication", 500)
	}

	// Invalidate cache for both old and new status
	s.invalidateMedicationCache(ctx, medication.PatientID, &oldStatus)
	s.invalidateMedicationCache(ctx, medication.PatientID, &medication.Status)

	s.logger.Info().
		Str("medication_id", medication.ID.String()).
		Str("patient_id", medication.PatientID.String()).
		Msg("Patient medication updated successfully")

	return nil
}

// DeletePatientMedication deletes a medication record
func (s *medicationService) DeletePatientMedication(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("medication_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient medication completed")
	}()

	// We need to get the medication first to know the patient ID and status for cache invalidation
	// This is a limitation - we don't have a GetMedicationByID method.
	// For now, we'll skip cache invalidation (not ideal).
	// In production, you would add a GetMedicationByID method to the repository.

	// Delete medication
	if err := s.medicationRepo.DeletePatientMedication(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("medication_id", id.String()).Msg("Failed to delete patient medication")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Medication not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete patient medication", 500)
	}

	// Note: Cache invalidation is skipped here because we don't have the patient ID and status.
	// In a production system, you would add a GetMedicationByID method to the repository.

	s.logger.Info().Str("medication_id", id.String()).Msg("Patient medication deleted successfully")
	return nil
}

// Validate patient medication
func (s *medicationService) validatePatientMedication(medication patients.PatientMedication) error {
	if medication.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}
	if strings.TrimSpace(medication.MedicationName) == "" {
		return fmt.Errorf("medication name is required")
	}
	if medication.Status != "" && !s.isValidMedicationStatus(medication.Status) {
		return fmt.Errorf("invalid medication status: %s", medication.Status)
	}

	// Validate dates
	if medication.StartDate != nil && medication.StartDate.After(time.Now()) {
		return fmt.Errorf("start date cannot be in the future")
	}

	if medication.EndDate != nil && medication.StartDate != nil && medication.EndDate.Before(*medication.StartDate) {
		return fmt.Errorf("end date cannot be before start date")
	}

	if medication.PrescriptionDate != nil && medication.PrescriptionDate.After(time.Now()) {
		return fmt.Errorf("prescription date cannot be in the future")
	}

	return nil
}

// Helper methods
func (s *medicationService) invalidateMedicationCache(ctx context.Context, patientID uuid.UUID, status *string) {
	cacheKeys := []string{
		fmt.Sprintf("medications:all:%s", patientID.String()),
		fmt.Sprintf("medications:active:%s", patientID.String()),
	}

	// Also invalidate status-specific cache
	if status != nil {
		cacheKeys = append(cacheKeys, fmt.Sprintf("medications:%s:%s", *status, patientID.String()))
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate medication cache")
		}
	}
}

func (s *medicationService) generateMedicationCacheKey(patientID uuid.UUID, status *string) string {
	if status != nil {
		return fmt.Sprintf("medications:%s:%s", *status, patientID.String())
	}
	return fmt.Sprintf("medications:all:%s", patientID.String())
}

func (s *medicationService) statusToString(status *string) string {
	if status == nil {
		return "all"
	}
	return *status
}

func (s *medicationService) isValidMedicationStatus(status string) bool {
	validStatuses := []string{"active", "discontinued", "completed", "on_hold", "planned"}
	for _, validStatus := range validStatuses {
		if strings.EqualFold(status, validStatus) {
			return true
		}
	}
	return false
}
