package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type userService struct {
	userRepo         repository.UserRepository
	patientRepo      repository.PatientRepository
	consentRepo      repository.ConsentRepository
	notificationRepo repository.NotificationRepository
	sessionRepo      repository.SessionRepository // Added this
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewUserService creates a new user service for health project
func NewUserService(
	userRepo repository.UserRepository,
	patientRepo repository.PatientRepository,
	consentRepo repository.ConsentRepository,
	notificationRepo repository.NotificationRepository,
	sessionRepo repository.SessionRepository, // Added this
	cache cache.Service,
	logger *zerolog.Logger,
) UserService {
	return &userService{
		userRepo:         userRepo,
		patientRepo:      patientRepo,
		consentRepo:      consentRepo,
		notificationRepo: notificationRepo,
		sessionRepo:      sessionRepo, // Added this
		cache:            cache,
		logger:           logger,
	}
}

// GetProfile gets user profile with additional info
func (s *userService) GetProfile(ctx context.Context, userID uuid.UUID) (domain.User, domain.PatientProfile, error) {
	cacheKey := fmt.Sprintf("user:profile:%s", userID.String())

	// Try cache first
	type CachedProfile struct {
		User    domain.User           `json:"user"`
		Profile domain.PatientProfile `json:"profile"`
	}
	var cached CachedProfile
	if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("Profile retrieved from cache")
		return cached.User, cached.Profile, nil
	}

	// Get user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return domain.User{}, domain.PatientProfile{}, domain.NewAppError(err, "User not found", 404)
	}

	// Get patient profile if user is a patient
	var patientProfile domain.PatientProfile
	if user.Role == "patient" {
		patientProfile, err = s.patientRepo.GetPatientProfileByUserID(ctx, userID)
		if err != nil && !errors.Is(err, domain.ErrPatientNotFound) {
			s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to get patient profile")
		}
	}

	// Cache the result
	cached = CachedProfile{
		User:    user,
		Profile: patientProfile,
	}
	if err := s.cache.Set(ctx, cacheKey, cached, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache user profile")
	}

	return user, patientProfile, nil
}

// GetUserByID gets user by ID
func (s *userService) GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error) {
	cacheKey := fmt.Sprintf("user:%s", userID.String())

	// Try cache first
	var user domain.User
	if err := s.cache.Get(ctx, cacheKey, &user); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("User retrieved from cache")
		return user, nil
	}

	// Fetch from database
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return domain.User{}, domain.NewAppError(err, "User not found", 404)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, user, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache user")
	}

	return user, nil
}

// UpdateProfile updates user profile
func (s *userService) UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error {
	// Get current user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return domain.NewAppError(err, "User not found", 404)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, userID) // Fixed: added ctx parameter

	// This is a simplified update - in reality, you'd have specific update methods
	// For now, we'll update the user object based on the updates map
	// Note: In production, you should validate and sanitize updates

	// Update patient profile if user is a patient
	if user.Role == "patient" {
		profile, err := s.patientRepo.GetPatientProfileByUserID(ctx, userID)
		if err == nil {
			// Update profile fields based on updates map
			// This is simplified - you'd need proper type checking
			s.updatePatientProfileFromMap(&profile, updates)

			if err := s.patientRepo.UpdatePatientProfile(ctx, profile); err != nil {
				s.logger.Error().Err(err).Msg("Failed to update patient profile")
				return domain.NewAppError(err, "Failed to update profile", 500)
			}
		}
	}

	s.logger.Info().Str("user_id", userID.String()).Msg("User profile updated")
	return nil
}

// UpdatePassword updates user password
func (s *userService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error { // Fixed: changed receiver to userService
	// Get user with password hash
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return domain.NewAppError(err, "User not found", 404)
	}

	// Check if user has email
	if user.Email == nil || *user.Email == "" {
		return domain.NewAppError(nil, "User does not have email set", 400)
	}

	// Get password hash using email
	_, passwordHash, err := s.userRepo.GetUserByEmail(ctx, *user.Email)
	if err != nil {
		return domain.NewAppError(err, "Failed to verify current password", 500)
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(currentPassword)); err != nil {
		return domain.NewAppError(domain.ErrInvalidCredentials, "Current password is incorrect", 401)
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash new password")
		return domain.NewAppError(err, "Failed to update password", 500)
	}

	// Update password
	if err := s.userRepo.UpdateUserPassword(ctx, userID, string(newHash)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to update password in database")
		return domain.NewAppError(err, "Failed to update password", 500)
	}

	// Invalidate all user sessions if sessionRepo exists
	if s.sessionRepo != nil {
		if err := s.sessionRepo.DeleteUserSessions(ctx, userID); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to delete user sessions")
		}
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, userID)

	s.logger.Info().Str("user_id", userID.String()).Msg("Password updated successfully")
	return nil
}

// DeleteProfile deactivates user profile
func (s *userService) DeleteProfile(ctx context.Context, userID uuid.UUID) error {
	// Deactivate user
	if err := s.userRepo.DeactivateUser(ctx, userID); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to deactivate user")
		return domain.NewAppError(err, "Failed to delete profile", 500)
	}

	// Delete all sessions if sessionRepo exists
	if s.sessionRepo != nil {
		if err := s.sessionRepo.DeleteUserSessions(ctx, userID); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to delete user sessions")
		}
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, userID)

	s.logger.Info().Str("user_id", userID.String()).Msg("User profile deactivated")
	return nil
}

// ListUsers lists users with filtering
func (s *userService) ListUsers(ctx context.Context, role string, limit, offset int) ([]domain.User, error) {
	users, err := s.userRepo.ListUsers(ctx, role, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to list users")
		return nil, domain.NewAppError(err, "Failed to list users", 500)
	}

	return users, nil
}

// GetConsent gets user consent settings
func (s *userService) GetConsent(ctx context.Context, userID uuid.UUID) (domain.PrivacyConsent, error) {
	consent, err := s.consentRepo.GetConsent(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get consent")
		return domain.PrivacyConsent{}, domain.NewAppError(err, "Failed to get consent", 500)
	}

	return consent, nil
}

// UpdateConsent updates user consent settings
func (s *userService) UpdateConsent(ctx context.Context, userID uuid.UUID, consent domain.PrivacyConsent) error {
	if err := s.consentRepo.UpdateConsent(ctx, consent); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update consent")
		return domain.NewAppError(err, "Failed to update consent", 500)
	}

	// Update user consent flags
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return domain.NewAppError(err, "User not found", 404)
	}

	user.SMSConsentGiven = consent.SMSCommunicationConsent
	user.POPIAConsentGiven = consent.HealthDataConsent
	user.ConsentDate = &[]time.Time{time.Now()}[0]

	// Invalidate cache
	s.invalidateUserCache(ctx, userID)

	s.logger.Info().Str("user_id", userID.String()).Msg("Consent updated")
	return nil
}

// Helper methods
func (s *userService) invalidateUserCache(ctx context.Context, userID uuid.UUID) { // Fixed: added ctx parameter
	cacheKeys := []string{
		fmt.Sprintf("user:%s", userID.String()),
		fmt.Sprintf("user:profile:%s", userID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate cache")
		}
	}
}

func (s *userService) updatePatientProfileFromMap(profile *domain.PatientProfile, updates map[string]interface{}) {
	// Simplified update - in reality, you'd need proper type assertions and validation
	if firstName, ok := updates["first_name"].(string); ok {
		profile.FirstName = firstName
	}
	if lastName, ok := updates["last_name"].(string); ok {
		profile.LastName = lastName
	}
	if preferredName, ok := updates["preferred_name"].(string); ok {
		profile.PreferredName = &preferredName
	}
	// Add more fields as needed
	profile.LastProfileUpdate = &[]time.Time{time.Now()}[0]
}
