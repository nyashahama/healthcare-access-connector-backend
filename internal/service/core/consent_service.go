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

// WithdrawConsent withdraws all consents for a user
func (s *consentService) WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("WithdrawConsent completed")
	}()

	// Validate reason
	if reason == "" {
		return domain.NewAppError(domain.ErrValidation, "Withdrawal reason is required", 400)
	}

	// Withdraw consent
	if err := s.consentRepo.WithdrawConsent(ctx, userID, reason); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to withdraw consent")
		return domain.NewAppError(err, "Failed to withdraw consent", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, userID)

	// Log consent withdrawal
	s.logConsentActivity(ctx, userID, "consent_withdrawn", core.PrivacyConsent{
		UserID:           userID,
		WithdrawalReason: &reason,
	})

	s.logger.Info().
		Str("user_id", userID.String()).
		Str("reason", reason).
		Msg("Consent withdrawn")

	return nil
}

// UpdateHealthDataConsent updates health data consent
func (s *consentService) UpdateHealthDataConsent(ctx context.Context, userID uuid.UUID, consent bool, version string) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Bool("consent", consent).
			Str("version", version).
			Msg("UpdateHealthDataConsent completed")
	}()

	// Validate version
	if version == "" {
		return domain.NewAppError(domain.ErrValidation, "Consent version is required", 400)
	}

	// Update health data consent
	if err := s.consentRepo.UpdateHealthDataConsent(ctx, userID, consent, version); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update health data consent")
		return domain.NewAppError(err, "Failed to update health data consent", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, userID)

	// Log health data consent update
	s.logConsentActivity(ctx, userID, "health_data_consent_updated", core.PrivacyConsent{
		UserID:                   userID,
		HealthDataConsent:        consent,
		HealthDataConsentVersion: &version,
	})

	s.logger.Info().
		Str("user_id", userID.String()).
		Bool("consent", consent).
		Str("version", version).
		Msg("Health data consent updated")

	return nil
}

// UpdateResearchConsent updates research consent
func (s *consentService) UpdateResearchConsent(ctx context.Context, userID uuid.UUID, consent bool) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Bool("consent", consent).
			Msg("UpdateResearchConsent completed")
	}()

	// Update research consent
	if err := s.consentRepo.UpdateResearchConsent(ctx, userID, consent); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update research consent")
		return domain.NewAppError(err, "Failed to update research consent", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, userID)

	// Log research consent update
	s.logConsentActivity(ctx, userID, "research_consent_updated", core.PrivacyConsent{
		UserID:          userID,
		ResearchConsent: consent,
	})

	s.logger.Info().
		Str("user_id", userID.String()).
		Bool("consent", consent).
		Msg("Research consent updated")

	return nil
}

// UpdateEmergencyAccessConsent updates emergency access consent
func (s *consentService) UpdateEmergencyAccessConsent(ctx context.Context, userID uuid.UUID, consent bool) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Bool("consent", consent).
			Msg("UpdateEmergencyAccessConsent completed")
	}()

	// Update emergency access consent
	if err := s.consentRepo.UpdateEmergencyAccessConsent(ctx, userID, consent); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update emergency access consent")
		return domain.NewAppError(err, "Failed to update emergency access consent", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, userID)

	// Log emergency access consent update
	s.logConsentActivity(ctx, userID, "emergency_access_consent_updated", core.PrivacyConsent{
		UserID:                 userID,
		EmergencyAccessConsent: consent,
	})

	s.logger.Info().
		Str("user_id", userID.String()).
		Bool("consent", consent).
		Msg("Emergency access consent updated")

	return nil
}

// UpdateCommunicationConsents updates communication consents
func (s *consentService) UpdateCommunicationConsents(ctx context.Context, userID uuid.UUID, sms, email bool) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Bool("sms", sms).
			Bool("email", email).
			Msg("UpdateCommunicationConsents completed")
	}()

	// Update communication consents
	if err := s.consentRepo.UpdateCommunicationConsents(ctx, userID, sms, email); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update communication consents")
		return domain.NewAppError(err, "Failed to update communication consents", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, userID)

	// Log communication consents update
	s.logConsentActivity(ctx, userID, "communication_consents_updated", core.PrivacyConsent{
		UserID:                    userID,
		SMSCommunicationConsent:   sms,
		EmailCommunicationConsent: email,
	})

	s.logger.Info().
		Str("user_id", userID.String()).
		Bool("sms", sms).
		Bool("email", email).
		Msg("Communication consents updated")

	return nil
}

// UpdateDataSharingConsent updates data sharing consent
func (s *consentService) UpdateDataSharingConsent(ctx context.Context, userID uuid.UUID, sharingPrefs map[string]interface{}) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Int("pref_count", len(sharingPrefs)).
			Msg("UpdateDataSharingConsent completed")
	}()

	// Validate sharing preferences
	if sharingPrefs == nil {
		sharingPrefs = make(map[string]interface{})
	}

	// Update data sharing consent
	if err := s.consentRepo.UpdateDataSharingConsent(ctx, userID, sharingPrefs); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update data sharing consent")
		return domain.NewAppError(err, "Failed to update data sharing consent", 500)
	}

	// Invalidate cache
	s.invalidateConsentCache(ctx, userID)

	// Log data sharing consent update
	s.logConsentActivity(ctx, userID, "data_sharing_consent_updated", core.PrivacyConsent{
		UserID:             userID,
		DataSharingConsent: sharingPrefs,
	})

	s.logger.Info().
		Str("user_id", userID.String()).
		Int("pref_count", len(sharingPrefs)).
		Msg("Data sharing consent updated")

	return nil
}

// GetConsentHistory gets consent history for a user
func (s *consentService) GetConsentHistory(ctx context.Context, userID uuid.UUID) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetConsentHistory completed")
	}()

	// Fetch consent history
	history, err := s.consentRepo.GetConsentHistory(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get consent history")
		return nil, domain.NewAppError(err, "Failed to get consent history", 500)
	}

	s.logger.Debug().
		Str("user_id", userID.String()).
		Int("count", len(history)).
		Msg("Consent history retrieved")

	return history, nil
}

// GetActiveConsentsByType gets active consents by type
func (s *consentService) GetActiveConsentsByType(ctx context.Context, consentType string) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("consent_type", consentType).
			Msg("GetActiveConsentsByType completed")
	}()

	// Validate consent type
	validTypes := map[string]bool{
		"health_data":      true,
		"research":         true,
		"emergency_access": true,
	}
	if !validTypes[consentType] {
		return nil, domain.NewAppError(domain.ErrValidation, "Invalid consent type", 400)
	}

	// Fetch active consents
	consents, err := s.consentRepo.GetActiveConsentsByType(ctx, consentType)
	if err != nil {
		s.logger.Error().Err(err).Str("consent_type", consentType).Msg("Failed to get active consents by type")
		return nil, domain.NewAppError(err, "Failed to get active consents", 500)
	}

	s.logger.Debug().
		Str("consent_type", consentType).
		Int("count", len(consents)).
		Msg("Active consents by type retrieved")

	return consents, nil
}

// GetExpiredConsents gets expired consents
func (s *consentService) GetExpiredConsents(ctx context.Context) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("GetExpiredConsents completed")
	}()

	// Fetch expired consents
	consents, err := s.consentRepo.GetExpiredConsents(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get expired consents")
		return nil, domain.NewAppError(err, "Failed to get expired consents", 500)
	}

	s.logger.Debug().
		Int("count", len(consents)).
		Msg("Expired consents retrieved")

	return consents, nil
}

// GetWithdrawnConsents gets withdrawn consents within a date range
func (s *consentService) GetWithdrawnConsents(ctx context.Context, startDate, endDate time.Time) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Time("start_date", startDate).
			Time("end_date", endDate).
			Msg("GetWithdrawnConsents completed")
	}()

	// Validate date range
	if startDate.After(endDate) {
		return nil, domain.NewAppError(domain.ErrValidation, "Start date must be before end date", 400)
	}

	// Fetch withdrawn consents
	consents, err := s.consentRepo.GetWithdrawnConsents(ctx, startDate, endDate)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get withdrawn consents")
		return nil, domain.NewAppError(err, "Failed to get withdrawn consents", 500)
	}

	s.logger.Debug().
		Time("start_date", startDate).
		Time("end_date", endDate).
		Int("count", len(consents)).
		Msg("Withdrawn consents retrieved")

	return consents, nil
}

// ExportConsentData exports consent data for a user
func (s *consentService) ExportConsentData(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("ExportConsentData completed")
	}()

	// Export consent data
	data, err := s.consentRepo.ExportConsentData(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to export consent data")
		return nil, domain.NewAppError(err, "Failed to export consent data", 500)
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Int("size_bytes", len(data)).
		Msg("Consent data exported")

	return data, nil
}

// NotifyConsentExpirations notifies users of expiring consents
func (s *consentService) NotifyConsentExpirations(ctx context.Context, daysBefore int) ([]uuid.UUID, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Int("days_before", daysBefore).
			Msg("NotifyConsentExpirations completed")
	}()

	// Validate days before
	if daysBefore < 1 || daysBefore > 30 {
		return nil, domain.NewAppError(domain.ErrValidation, "Days before must be between 1 and 30", 400)
	}

	// Get users with expiring consents
	userIDs, err := s.consentRepo.NotifyConsentExpirations(ctx, daysBefore)
	if err != nil {
		s.logger.Error().Err(err).Int("days_before", daysBefore).Msg("Failed to get expiring consents")
		return nil, domain.NewAppError(err, "Failed to get expiring consents", 500)
	}

	s.logger.Info().
		Int("days_before", daysBefore).
		Int("user_count", len(userIDs)).
		Msg("Consent expirations notification list generated")

	return userIDs, nil
}

// StartConsentExpirationJob starts background job for consent expiration notifications
func (s *consentService) StartConsentExpirationJob(interval time.Duration, notifyDaysBefore int) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Info().
		Dur("interval", interval).
		Int("notify_days_before", notifyDaysBefore).
		Msg("Starting consent expiration job")

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if _, err := s.NotifyConsentExpirations(ctx, notifyDaysBefore); err != nil {
			s.logger.Warn().Err(err).Msg("Consent expiration job failed")
		}
		cancel()
	}
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
