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

type patientService struct {
	patientRepo      repository.PatientProfileRepository
	userRepo         repository.UserRepository
	notificationRepo repository.NotificationRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewPatientService creates a new patient service
func NewPatientService(
	patientRepo repository.PatientProfileRepository,
	userRepo repository.UserRepository,
	notificationRepo repository.NotificationRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.PatientService {
	return &patientService{
		patientRepo:      patientRepo,
		userRepo:         userRepo,
		notificationRepo: notificationRepo,
		cache:            cache,
		logger:           logger,
	}
}

// CreatePatientProfile creates a new patient profile
func (s *patientService) CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("user_id", profile.UserID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Create patient profile completed")
	}()

	// Validate input
	if err := s.validatePatientProfile(profile); err != nil {
		return patients.PatientProfile{}, domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Set default values if not provided
	if profile.Country == "" {
		profile.Country = "South Africa"
	}
	if len(profile.LanguagePreferences) == 0 {
		profile.LanguagePreferences = []string{"en", "af", "zu"}
	}
	if profile.PreferredCommunicationMethod == "" {
		profile.PreferredCommunicationMethod = "sms"
	}
	if profile.Timezone == "" {
		profile.Timezone = "Africa/Johannesburg"
	}

	// Set timestamps
	now := time.Now()
	profile.ID = uuid.New()
	profile.CreatedAt = now
	profile.UpdatedAt = now
	profile.LastProfileUpdate = &now

	// Create patient profile
	created, err := s.patientRepo.CreatePatientProfile(ctx, profile)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", profile.UserID.String()).Msg("Failed to create patient profile")
		if strings.Contains(err.Error(), "already exists") {
			return patients.PatientProfile{}, domain.NewAppError(domain.ErrDuplicate, "Patient profile already exists for this user", 409)
		}
		if strings.Contains(err.Error(), "national ID already registered") {
			return patients.PatientProfile{}, domain.NewAppError(domain.ErrDuplicate, "National ID already registered", 409)
		}
		return patients.PatientProfile{}, domain.NewAppError(err, "Failed to create patient profile", 500)
	}

	// Update user profile completion percentage
	if err := s.userRepo.UpdateUserProfileCompletion(ctx, profile.UserID, 60); err != nil {
		s.logger.Warn().Err(err).Str("user_id", profile.UserID.String()).Msg("Failed to update user profile completion")
	}

	// Invalidate cache
	s.invalidatePatientCache(ctx, profile.UserID)

	s.logger.Info().
		Str("patient_id", created.ID.String()).
		Str("user_id", created.UserID.String()).
		Str("name", fmt.Sprintf("%s %s", created.FirstName, created.LastName)).
		Msg("Patient profile created successfully")

	return created, nil
}

// GetPatientProfile retrieves a patient profile by user ID
func (s *patientService) GetPatientProfile(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("user_id", userID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient profile completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("patient:profile:%s", userID.String())
	var profile patients.PatientProfile
	if err := s.cache.Get(ctx, cacheKey, &profile); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("Patient profile retrieved from cache")
		return profile, nil
	}

	// Fetch from database
	profile, err := s.patientRepo.GetPatientProfileByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("user_id", userID.String()).Msg("Patient profile not found")
			return patients.PatientProfile{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient profile not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get patient profile")
		return patients.PatientProfile{}, domain.NewAppError(err, "Failed to get patient profile", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, profile, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient profile")
	}

	return profile, nil
}

// GetPatientProfileByID retrieves a patient profile by ID
func (s *patientService) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient profile by ID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("patient:by_id:%s", id.String())
	var profile patients.PatientProfile
	if err := s.cache.Get(ctx, cacheKey, &profile); err == nil {
		s.logger.Debug().Str("patient_id", id.String()).Msg("Patient profile retrieved from cache")
		return profile, nil
	}

	// Fetch from database
	profile, err := s.patientRepo.GetPatientProfileByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("patient_id", id.String()).Msg("Patient profile not found")
			return patients.PatientProfile{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient profile not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", id.String()).Msg("Failed to get patient profile")
		return patients.PatientProfile{}, domain.NewAppError(err, "Failed to get patient profile", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, profile, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache patient profile")
	}

	return profile, nil
}

// GetPatientProfileByNationalID retrieves a patient profile by national ID
func (s *patientService) GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("national_id", maskNationalID(nationalID)).
			Dur("duration_ms", time.Since(start)).
			Msg("Get patient profile by national ID completed")
	}()

	if nationalID == "" {
		return patients.PatientProfile{}, domain.NewAppError(domain.ErrValidation, "National ID is required", 400)
	}

	// Fetch from database
	profile, err := s.patientRepo.GetPatientProfileByNationalID(ctx, nationalID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Debug().Str("national_id", maskNationalID(nationalID)).Msg("Patient profile not found")
			return patients.PatientProfile{}, domain.NewAppError(domain.ErrPatientNotFound, "Patient profile not found", 404)
		}
		s.logger.Error().Err(err).Str("national_id", maskNationalID(nationalID)).Msg("Failed to get patient profile")
		return patients.PatientProfile{}, domain.NewAppError(err, "Failed to get patient profile", 500)
	}

	return profile, nil
}

// UpdatePatientProfile updates an existing patient profile
func (s *patientService) UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", profile.ID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Update patient profile completed")
	}()

	// Validate input
	if err := s.validatePatientProfile(profile); err != nil {
		return domain.NewAppError(domain.ErrValidation, err.Error(), 400)
	}

	// Update timestamps
	now := time.Now()
	profile.UpdatedAt = now
	profile.LastProfileUpdate = &now

	// Update patient profile
	if err := s.patientRepo.UpdatePatientProfile(ctx, profile); err != nil {
		s.logger.Error().Err(err).Str("patient_id", profile.ID.String()).Msg("Failed to update patient profile")
		return domain.NewAppError(err, "Failed to update patient profile", 500)
	}

	// Update user profile completion percentage
	if err := s.userRepo.UpdateUserProfileCompletion(ctx, profile.UserID, 80); err != nil {
		s.logger.Warn().Err(err).Str("user_id", profile.UserID.String()).Msg("Failed to update user profile completion")
	}

	// Invalidate cache
	s.invalidatePatientCache(ctx, profile.UserID)

	s.logger.Info().
		Str("patient_id", profile.ID.String()).
		Str("user_id", profile.UserID.String()).
		Msg("Patient profile updated successfully")

	return nil
}

// DeletePatientProfile deletes a patient profile
func (s *patientService) DeletePatientProfile(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("patient_id", id.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient profile completed")
	}()

	// Get profile first to get user ID for cache invalidation
	profile, err := s.patientRepo.GetPatientProfileByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		s.logger.Warn().Err(err).Str("patient_id", id.String()).Msg("Failed to get patient profile before deletion")
	}

	// Delete patient profile
	if err := s.patientRepo.DeletePatientProfile(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("patient_id", id.String()).Msg("Failed to delete patient profile")
		return domain.NewAppError(err, "Failed to delete patient profile", 500)
	}

	// Update user profile completion percentage
	if err == nil {
		if err := s.userRepo.UpdateUserProfileCompletion(ctx, profile.UserID, 20); err != nil {
			s.logger.Warn().Err(err).Str("user_id", profile.UserID.String()).Msg("Failed to update user profile completion")
		}

		// Invalidate cache
		s.invalidatePatientCache(ctx, profile.UserID)
	}

	s.logger.Info().Str("patient_id", id.String()).Msg("Patient profile deleted successfully")
	return nil
}

// DeletePatientProfileByUserID deletes a patient profile by user ID
func (s *patientService) DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Str("user_id", userID.String()).
			Dur("duration_ms", time.Since(start)).
			Msg("Delete patient profile by user ID completed")
	}()

	// Delete patient profile
	if err := s.patientRepo.DeletePatientProfileByUserID(ctx, userID); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to delete patient profile")
		return domain.NewAppError(err, "Failed to delete patient profile", 500)
	}

	// Update user profile completion percentage
	if err := s.userRepo.UpdateUserProfileCompletion(ctx, userID, 20); err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to update user profile completion")
	}

	// Invalidate cache
	s.invalidatePatientCache(ctx, userID)

	s.logger.Info().Str("user_id", userID.String()).Msg("Patient profile deleted successfully")
	return nil
}

// SearchPatients searches patients with advanced filtering
func (s *patientService) SearchPatients(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("Search patients completed")
	}()

	// Validate limit and offset
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}
	if params.Offset < 0 {
		params.Offset = 0
	}

	// Generate cache key based on search parameters
	cacheKey := s.generateSearchCacheKey(params)
	if cacheKey != "" {
		var cachedResults []patients.PatientProfile
		if err := s.cache.Get(ctx, cacheKey, &cachedResults); err == nil {
			s.logger.Debug().Msg("Search results retrieved from cache")
			return cachedResults, nil
		}
	}

	// For now, return empty slice -  this would query the database
	// We would need to add a SearchPatients method to the repository
	results := []patients.PatientProfile{}

	// Cache the results if we have a cache key
	if cacheKey != "" && len(results) > 0 {
		if err := s.cache.Set(ctx, cacheKey, results, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache search results")
		}
	}

	s.logger.Debug().Int("count", len(results)).Msg("Search patients completed")
	return results, nil
}

// GetDemographicsSummary gets aggregated patient demographics
func (s *patientService) GetDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("Get demographics summary completed")
	}()

	// Try cache first
	cacheKey := "patient:demographics:summary"
	var summary patients.PatientDemographicsSummary
	if err := s.cache.Get(ctx, cacheKey, &summary); err == nil {
		s.logger.Debug().Msg("Demographics summary retrieved from cache")
		return summary, nil
	}

	// For now, return empty summary -  this would calculate statistics
	summary = patients.PatientDemographicsSummary{
		TotalPatients:        0,
		ProvincesCovered:     0,
		CitiesCovered:        0,
		WithMedicalAid:       0,
		RequiringInterpreter: 0,
		MarketingOptIn:       0,
		AverageAge:           0.0,
	}

	// Cache the summary
	if err := s.cache.Set(ctx, cacheKey, summary, 30*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache demographics summary")
	}

	return summary, nil
}

// GetPatientByUserID is an alias for GetPatientProfile for interface compatibility
func (s *patientService) GetPatientByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	return s.GetPatientProfile(ctx, userID)
}

// Validate patient profile
func (s *patientService) validatePatientProfile(profile patients.PatientProfile) error {
	if profile.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if strings.TrimSpace(profile.FirstName) == "" {
		return fmt.Errorf("first name is required")
	}
	if strings.TrimSpace(profile.LastName) == "" {
		return fmt.Errorf("last name is required")
	}
	if profile.DateOfBirth != nil && profile.DateOfBirth.After(time.Now()) {
		return fmt.Errorf("date of birth cannot be in the future")
	}
	if profile.NationalIDNumber != nil && len(*profile.NationalIDNumber) < 13 {
		return fmt.Errorf("national ID must be at least 13 characters")
	}
	return nil
}

// Helper methods
func (s *patientService) invalidatePatientCache(ctx context.Context, userID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("patient:profile:%s", userID.String()),
		fmt.Sprintf("patient:by_id:*"), // Would need pattern matching
		fmt.Sprintf("user:profile:%s", userID.String()),
		"patient:demographics:summary",
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate cache")
		}
	}
}

func (s *patientService) generateSearchCacheKey(params patients.AdvancedSearchParams) string {
	// Generate a unique cache key based on search parameters
	//  this would create a hash of all parameters
	return ""
}

func maskNationalID(nationalID string) string {
	if len(nationalID) <= 4 {
		return "***"
	}
	return "***" + nationalID[len(nationalID)-4:]
}
