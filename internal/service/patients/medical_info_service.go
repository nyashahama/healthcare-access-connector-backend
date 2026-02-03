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

type medicalInfoService struct {
	medicalInfoRepo repository.PatientMedicalInfoRepository
	patientRepo     repository.PatientProfileRepository
	cache           cache.Service
	logger          *zerolog.Logger
}

// NewMedicalInfoService creates a new medical info service
func NewMedicalInfoService(
	medicalInfoRepo repository.PatientMedicalInfoRepository,
	patientRepo repository.PatientProfileRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.MedicalInfoService {
	return &medicalInfoService{
		medicalInfoRepo: medicalInfoRepo,
		patientRepo:     patientRepo,
		cache:           cache,
		logger:          logger,
	}
}

// CreateMedicalInfo creates medical information for a patient
func (s *medicalInfoService) CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) (patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", info.PatientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Create medical info completed")
	}()

	// Validate input
	if err := s.validateMedicalInfo(info); err != nil {
		return patients.PatientMedicalInfo{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, info.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", info.PatientID.String()).Msg("Patient not found")
			return patients.PatientMedicalInfo{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", info.PatientID.String()).Msg("Failed to verify patient")
		return patients.PatientMedicalInfo{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Check if medical info already exists
	existing, err := s.medicalInfoRepo.GetMedicalInfoByPatientID(ctx, info.PatientID)
	if err == nil && existing.ID != uuid.Nil {
		s.logger.Debug().Str("patient_id", info.PatientID.String()).Msg("Medical info already exists for patient")
		return patients.PatientMedicalInfo{}, domain.NewAppError(domain.ErrDuplicate, "Medical information already exists for this patient", 409)
	}

	// Set timestamps
	now := time.Now()
	info.ID = uuid.New()
	info.CreatedAt = now
	info.UpdatedAt = now

	// Create medical info
	created, err := s.medicalInfoRepo.CreateMedicalInfo(ctx, info)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", info.PatientID.String()).
			Msg("Failed to create medical info")
		return patients.PatientMedicalInfo{}, domain.NewAppError(err, "Failed to create medical info", 500)
	}

	// Invalidate cache
	s.invalidateMedicalInfoCache(ctx, info.PatientID)

	s.logger.Info().
		Str("medical_info_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Msg("Medical info created successfully")

	return created, nil
}

// GetMedicalInfoByID retrieves medical information by ID
func (s *medicalInfoService) GetMedicalInfoByID(ctx context.Context, id uuid.UUID) (patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("medical_info_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get medical info by ID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("medical_info:%s", id.String())
	var info patients.PatientMedicalInfo
	if err := s.cache.Get(ctx, cacheKey, &info); err == nil {
		s.logger.Debug().Str("medical_info_id", id.String()).Msg("Medical info retrieved from cache")
		return info, nil
	}

	// Fetch from database
	info, err := s.medicalInfoRepo.GetMedicalInfoByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("medical_info_id", id.String()).Msg("Medical info not found")
			return patients.PatientMedicalInfo{}, domain.NewAppError(domain.ErrNotFound, "Medical information not found", 404)
		}
		s.logger.Error().Err(err).Str("medical_info_id", id.String()).Msg("Failed to get medical info")
		return patients.PatientMedicalInfo{}, domain.NewAppError(err, "Failed to get medical info", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, info, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache medical info")
	}

	return info, nil
}

// GetMedicalInfoByPatientID retrieves medical information by patient ID
func (s *medicalInfoService) GetMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get medical info by patient ID completed")
	}()

	// Verify patient exists
	_, err := s.patientRepo.GetPatientProfileByID(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient not found")
			return patients.PatientMedicalInfo{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to verify patient")
		return patients.PatientMedicalInfo{}, domain.NewAppError(err, "Failed to verify patient", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("medical_info:patient:%s", patientID.String())
	var info patients.PatientMedicalInfo
	if err := s.cache.Get(ctx, cacheKey, &info); err == nil {
		s.logger.Debug().Str("patient_id", patientID.String()).Msg("Medical info retrieved from cache")
		return info, nil
	}

	// Fetch from database
	info, err = s.medicalInfoRepo.GetMedicalInfoByPatientID(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Medical info not found for patient")
			return patients.PatientMedicalInfo{}, domain.NewAppError(domain.ErrNotFound, "Medical information not found for this patient", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get medical info")
		return patients.PatientMedicalInfo{}, domain.NewAppError(err, "Failed to get medical info", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, info, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache medical info")
	}

	return info, nil
}

// UpdateMedicalInfo updates medical information
func (s *medicalInfoService) UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("medical_info_id", info.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update medical info completed")
	}()

	// Validate input
	if err := s.validateMedicalInfo(info); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Get existing medical info to verify it exists
	existing, err := s.medicalInfoRepo.GetMedicalInfoByPatientID(ctx, info.PatientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", info.PatientID.String()).Msg("Medical info not found for patient")
			return domain.NewAppError(domain.ErrNotFound, "Medical information not found for this patient", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", info.PatientID.String()).Msg("Failed to get medical info")
		return domain.NewAppError(err, "Failed to get medical info", 500)
	}

	// Update timestamps
	info.UpdatedAt = time.Now()
	info.ID = existing.ID // Ensure we're updating the correct record

	// Update medical info
	if err := s.medicalInfoRepo.UpdateMedicalInfo(ctx, info); err != nil {
		s.logger.Error().Err(err).
			Str("medical_info_id", info.ID.String()).
			Str("patient_id", info.PatientID.String()).
			Msg("Failed to update medical info")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Medical information not found", 404)
		}
		return domain.NewAppError(err, "Failed to update medical info", 500)
	}

	// Invalidate cache
	s.invalidateMedicalInfoCache(ctx, info.PatientID)

	s.logger.Info().
		Str("medical_info_id", info.ID.String()).
		Str("patient_id", info.PatientID.String()).
		Msg("Medical info updated successfully")

	return nil
}

// DeleteMedicalInfoByPatientID deletes medical information by patient ID
func (s *medicalInfoService) DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", patientID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete medical info by patient ID completed")
	}()

	// Delete medical info
	if err := s.medicalInfoRepo.DeleteMedicalInfoByPatientID(ctx, patientID); err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to delete medical info")

		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(domain.ErrNotFound, "Medical information not found", 404)
		}
		return domain.NewAppError(err, "Failed to delete medical info", 500)
	}

	// Invalidate cache
	s.invalidateMedicalInfoCache(ctx, patientID)

	s.logger.Info().Str("patient_id", patientID.String()).Msg("Medical info deleted successfully")
	return nil
}

// Validate medical information
func (s *medicalInfoService) validateMedicalInfo(info patients.PatientMedicalInfo) error {
	if info.PatientID == uuid.Nil {
		return fmt.Errorf("patient ID is required")
	}

	// Validate blood type if provided
	if info.BloodType != nil && !s.isValidBloodType(*info.BloodType) {
		return fmt.Errorf("invalid blood type: %s", *info.BloodType)
	}

	// Validate dates
	if info.BloodTypeLastTested != nil && info.BloodTypeLastTested.After(time.Now()) {
		return fmt.Errorf("blood type last tested date cannot be in the future")
	}

	if info.LastMeasuredDate != nil && info.LastMeasuredDate.After(time.Now()) {
		return fmt.Errorf("last measured date cannot be in the future")
	}

	// Validate numeric values
	if info.HeightCm != nil && *info.HeightCm <= 0 {
		return fmt.Errorf("height must be positive")
	}

	if info.WeightKg != nil && *info.WeightKg <= 0 {
		return fmt.Errorf("weight must be positive")
	}

	return nil
}

// Helper methods
func (s *medicalInfoService) invalidateMedicalInfoCache(ctx context.Context, patientID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("medical_info:patient:%s", patientID.String()),
		// Also invalidate by ID if we have it cached
		// We would need to know the medical info ID, but we can't get it from just patient ID
		// In production, you might use a different cache strategy
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate medical info cache")
		}
	}
}

func (s *medicalInfoService) isValidBloodType(bloodType string) bool {
	validBloodTypes := []string{"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"}
	for _, validType := range validBloodTypes {
		if bloodType == validType {
			return true
		}
	}
	return false
}
