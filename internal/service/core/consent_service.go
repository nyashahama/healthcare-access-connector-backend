package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type consentService struct {
	consentRepo repository.ConsentRepository
	userRepo    repository.UserRepository
	auditRepo   repository.AuditRepository
	cache       cache.Service
	logger      *zerolog.Logger
}

// NewConsentService creates a new consent service
func NewConsentService(
	consentRepo repository.ConsentRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ConsentService {
	return &consentService{
		consentRepo: consentRepo,
		userRepo:    userRepo,
		auditRepo:   auditRepo,
		cache:       cache,
		logger:      logger,
	}
}

// GetPrivacyConsent gets privacy consent for a user
func (s *consentService) GetPrivacyConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetPrivacyConsent completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("consent:privacy:%s", userID.String())
	var consent core.PrivacyConsent
	if err := s.cache.Get(ctx, cacheKey, &consent); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("Privacy consent retrieved from cache")
		return consent, nil
	}

	// Fetch from database
	consent, err := s.consentRepo.GetPrivacyConsent(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// Create default consent if not found
			return s.createDefaultPrivacyConsent(ctx, userID)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get privacy consent")
		return core.PrivacyConsent{}, domain.NewAppError(err, "Failed to get privacy consent", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, consent, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache privacy consent")
	}

	return consent, nil
}

// CreatePrivacyConsent creates privacy consent for a user
func (s *consentService) CreatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", consent.UserID.String()).
			Msg("CreatePrivacyConsent completed")
	}()

	// Validate input
	if err := s.validatePrivacyConsent(consent); err != nil {
		return core.PrivacyConsent{}, err
	}

	// Check if consent already exists
	existing, err := s.consentRepo.GetPrivacyConsent(ctx, consent.UserID)
	if err == nil && existing.ID != uuid.Nil {
		return core.PrivacyConsent{}, domain.NewAppError(domain.ErrValidation, "Privacy consent already exists for user", 400)
	}

	// Create consent
	createdConsent, err := s.consentRepo.CreatePrivacyConsent(ctx, consent)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", consent.UserID.String()).Msg("Failed to create privacy consent")
		return core.PrivacyConsent{}, domain.NewAppError(err, "Failed to create privacy consent", 500)
	}

	// Cache the result
	cacheKey := fmt.Sprintf("consent:privacy:%s", consent.UserID.String())
	if err := s.cache.Set(ctx, cacheKey, createdConsent, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache privacy consent")
	}

	// Log consent creation
	s.logConsentActivity(ctx, consent.UserID, "privacy_consent_created", createdConsent)

	s.logger.Info().
		Str("user_id", consent.UserID.String()).
		Msg("Privacy consent created")

	return createdConsent, nil
}

// UpdatePrivacyConsent updates privacy consent for a user
func (s *consentService) UpdatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", consent.UserID.String()).
			Msg("UpdatePrivacyConsent completed")
	}()

	// Validate input
	if err := s.validatePrivacyConsent(consent); err != nil {
		return err
	}

	// Get existing consent to compare
	existing, err := s.GetPrivacyConsent(ctx, consent.UserID)
	fmt.Print(existing)
	if err != nil {
		return err
	}

	// Update consent
	if err := s.consentRepo.UpdatePrivacyConsent(ctx, consent); err != nil {
		s.logger.Error().Err(err).Str("user_id", consent.UserID.String()).Msg("Failed to update privacy consent")
		return domain.NewAppError(err, "Failed to update privacy consent", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, consent.UserID)

	// Log consent update
	s.logConsentActivity(ctx, consent.UserID, "privacy_consent_updated", consent)

	s.logger.Info().
		Str("user_id", consent.UserID.String()).
		Msg("Privacy consent updated")

	return nil
}

// Helper methods

func (s *consentService) createDefaultPrivacyConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error) {
	// Create default consent
	defaultConsent := core.PrivacyConsent{
		UserID:                     userID,
		HealthDataConsent:          true,
		HealthDataConsentDate:      timePtr(time.Now()),
		HealthDataConsentVersion:   stringPtr("1.0"),
		ResearchConsent:            false,
		EmergencyAccessConsent:     true,
		EmergencyAccessConsentDate: timePtr(time.Now()),
		SMSCommunicationConsent:    true,
		EmailCommunicationConsent:  true,
		DataSharingConsent:         make(map[string]interface{}),
		SpecialCategoriesConsent:   make(map[string]interface{}),
		ConsentWithdrawn:           false,
		CreatedAt:                  time.Now(),
		UpdatedAt:                  time.Now(),
	}

	// Create consent in database
	createdConsent, err := s.consentRepo.CreatePrivacyConsent(ctx, defaultConsent)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to create default privacy consent")
		return core.PrivacyConsent{}, domain.NewAppError(err, "Failed to create default privacy consent", 500)
	}

	// Cache the result
	cacheKey := fmt.Sprintf("consent:privacy:%s", userID.String())
	if err := s.cache.Set(ctx, cacheKey, createdConsent, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache default privacy consent")
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Msg("Default privacy consent created")

	return createdConsent, nil
}

func (s *consentService) validatePrivacyConsent(consent core.PrivacyConsent) error {
	// Validate user ID
	if consent.UserID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Validate health data consent version
	if consent.HealthDataConsent && (consent.HealthDataConsentVersion == nil || *consent.HealthDataConsentVersion == "") {
		return domain.NewAppError(domain.ErrValidation, "Health data consent version is required", 400)
	}

	return nil
}

func (s *consentService) invalidateConsentCache(ctx context.Context, userID uuid.UUID) {
	cacheKey := fmt.Sprintf("consent:privacy:%s", userID.String())
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to invalidate consent cache")
	}
}

func (s *consentService) logConsentActivity(ctx context.Context, userID uuid.UUID, activityType string, consent core.PrivacyConsent) {
	// Create activity log
	activity := core.UserActivity{
		UserID:       &userID,
		ActivityType: activityType,
		ActivityDetails: map[string]interface{}{
			"consent_type":             "privacy",
			"health_data_consent":      consent.HealthDataConsent,
			"research_consent":         consent.ResearchConsent,
			"emergency_access_consent": consent.EmergencyAccessConsent,
			"sms_consent":              consent.SMSCommunicationConsent,
			"email_consent":            consent.EmailCommunicationConsent,
		},
		ResourceType: stringPtr("consent"),
		ResourceID:   &consent.ID,
		PerformedAt:  time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to log consent activity")
		}
	}()
}

func timePtr(t time.Time) *time.Time {
	return &t
}
