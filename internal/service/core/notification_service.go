package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type notificationService struct {
	notificationRepo repository.NotificationRepository
	userRepo         repository.UserRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

func (s *notificationService) cacheAvailable() bool {
	return s != nil && s.cache != nil && s.cache.IsAvailable()
}

// NewNotificationService creates a new notification service
func NewNotificationService(
	notificationRepo repository.NotificationRepository,
	userRepo repository.UserRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.NotificationService {
	return &notificationService{
		notificationRepo: notificationRepo,
		userRepo:         userRepo,
		cache:            cache,
		logger:           logger,
	}
}

// GetPreferences gets notification preferences for a user
func (s *notificationService) GetPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetPreferences completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("notification:preferences:%s", userID.String())
	var prefs core.NotificationPreferences
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &prefs); err == nil {
			s.logger.Debug().Str("user_id", userID.String()).Msg("Notification preferences retrieved from cache")
			return prefs, nil
		}
	}

	// Fetch from database
	prefs, err := s.notificationRepo.GetNotificationPreferences(ctx, userID)
	if err != nil {
		if err == domain.ErrPreferencesNotFound {
			// Create default preferences if not found
			return s.createDefaultPreferences(ctx, userID)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get notification preferences")
		return core.NotificationPreferences{}, domain.NewAppError(err, "Failed to get notification preferences", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, prefs, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache notification preferences")
		}
	}

	return prefs, nil
}

// UpdatePreferences updates notification preferences for a user
func (s *notificationService) UpdatePreferences(ctx context.Context, prefs core.NotificationPreferences) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", prefs.UserID.String()).
			Msg("UpdatePreferences completed")
	}()

	// Validate input
	if err := s.validatePreferences(prefs); err != nil {
		return err
	}

	// Update preferences in database
	if err := s.notificationRepo.UpdateNotificationPreferences(ctx, prefs); err != nil {
		s.logger.Error().Err(err).Str("user_id", prefs.UserID.String()).Msg("Failed to update notification preferences")
		return domain.NewAppError(err, "Failed to update notification preferences", 500)
	}

	// Invalidate cache
	s.invalidatePreferencesCache(ctx, prefs.UserID)

	s.logger.Info().
		Str("user_id", prefs.UserID.String()).
		Msg("Notification preferences updated")

	return nil
}

// CanSendNotification checks if a notification can be sent to a user
func (s *notificationService) CanSendNotification(ctx context.Context, userID uuid.UUID, notificationType, channel string) (bool, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Str("notification_type", notificationType).
			Str("channel", channel).
			Msg("CanSendNotification completed")
	}()

	// Get user preferences
	prefs, err := s.GetPreferences(ctx, userID)
	if err != nil {
		return false, err
	}

	// Check channel-specific settings
	switch channel {
	case "sms":
		if !prefs.SMSEnabled {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Str("notification_type", notificationType).
				Msg("SMS notifications disabled")
			return false, nil
		}
	case "email":
		if !prefs.EmailEnabled {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Str("notification_type", notificationType).
				Msg("Email notifications disabled")
			return false, nil
		}
	case "push":
		if !prefs.PushEnabled {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Str("notification_type", notificationType).
				Msg("Push notifications disabled")
			return false, nil
		}
	default:
		return false, domain.NewAppError(domain.ErrValidation, "Invalid notification channel", 400)
	}

	// Check notification type-specific settings
	switch notificationType {
	case "appointment":
		if !prefs.AppointmentReminders {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Msg("Appointment reminders disabled")
			return false, nil
		}
	case "health_tips":
		if !prefs.HealthTips {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Msg("Health tips disabled")
			return false, nil
		}
	case "medication":
		if !prefs.MedicationReminders {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Msg("Medication reminders disabled")
			return false, nil
		}
	case "emergency":
		if !prefs.EmergencyAlerts {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Msg("Emergency alerts disabled")
			return false, nil
		}
	case "system":
		if !prefs.SystemMaintenance {
			s.logger.Debug().
				Str("user_id", userID.String()).
				Msg("System maintenance notifications disabled")
			return false, nil
		}
		// Add other notification types as needed
	}

	// Check quiet hours
	if prefs.QuietHoursStart != nil && prefs.QuietHoursEnd != nil {
		now := time.Now()
		currentTime := now.Format("15:04:05")

		// Simple string comparison for time ranges
		if currentTime >= *prefs.QuietHoursStart && currentTime <= *prefs.QuietHoursEnd {
			// Don't send non-emergency notifications during quiet hours
			if notificationType != "emergency" {
				s.logger.Debug().
					Str("user_id", userID.String()).
					Str("current_time", currentTime).
					Str("quiet_hours", *prefs.QuietHoursStart+"-"+*prefs.QuietHoursEnd).
					Msg("Within quiet hours, notification suppressed")
				return false, nil
			}
		}
	}

	return true, nil
}

// Helper methods

func (s *notificationService) createDefaultPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error) {
	// Get user to determine default language
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to get user for default preferences")
		// Use English as default
	}

	defaultLanguage := "en"
	if user.Phone != nil && strings.HasPrefix(*user.Phone, "+27") {
		// South African users - use English as default but could add Afrikaans/Zulu detection
		defaultLanguage = "en"
	}

	// Create default preferences
	defaultPrefs := core.NotificationPreferences{
		ID:                             uuid.New(),
		UserID:                         userID,
		SMSEnabled:                     true,
		EmailEnabled:                   true,
		PushEnabled:                    true,
		WhatsappEnabled:                false,
		AppointmentReminders:           true,
		AppointmentReminderHoursBefore: 24,
		HealthTips:                     true,
		HealthTipsFrequency:            "weekly",
		MedicationReminders:            true,
		PrescriptionUpdates:            true,
		ClinicUpdates:                  true,
		Newsletter:                     false,
		EmergencyAlerts:                true,
		SystemMaintenance:              true,
		NotificationLanguage:           defaultLanguage,
		CreatedAt:                      time.Now(),
		UpdatedAt:                      time.Now(),
	}

	// Save to database
	createdPrefs, err := s.notificationRepo.CreateNotificationPreferences(ctx, defaultPrefs)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to create default notification preferences")
		return core.NotificationPreferences{}, domain.NewAppError(err, "Failed to create default notification preferences", 500)
	}

	// Cache the result
	cacheKey := fmt.Sprintf("notification:preferences:%s", userID.String())
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, createdPrefs, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache default notification preferences")
		}
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Msg("Default notification preferences created")

	return createdPrefs, nil
}

func (s *notificationService) validatePreferences(prefs core.NotificationPreferences) error {
	// Validate user ID
	if prefs.UserID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Validate health tips frequency if health tips are enabled
	if prefs.HealthTips && prefs.HealthTipsFrequency != "" {
		validFrequencies := map[string]bool{
			"daily":   true,
			"weekly":  true,
			"monthly": true,
			"never":   true,
		}
		if !validFrequencies[prefs.HealthTipsFrequency] {
			return domain.NewAppError(domain.ErrValidation, "Invalid health tips frequency", 400)
		}
	}

	// Validate appointment reminder hours
	if prefs.AppointmentReminderHoursBefore < 0 {
		return domain.NewAppError(domain.ErrValidation, "Appointment reminder hours must be positive", 400)
	}

	// Validate language if provided
	if prefs.NotificationLanguage != "" {
		validLanguages := map[string]bool{
			"en": true, // English
			"af": true, // Afrikaans
			"zu": true, // Zulu
			"xh": true, // Xhosa
		}
		if !validLanguages[prefs.NotificationLanguage] {
			return domain.NewAppError(domain.ErrValidation, "Invalid notification language", 400)
		}
	}

	return nil
}

func (s *notificationService) invalidatePreferencesCache(ctx context.Context, userID uuid.UUID) {
	if !s.cacheAvailable() {
		return
	}

	cacheKey := fmt.Sprintf("notification:preferences:%s", userID.String())
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.logger.Warn().Err(err).Str("key", cacheKey).Msg("Failed to invalidate notification preferences cache")
	}
}
