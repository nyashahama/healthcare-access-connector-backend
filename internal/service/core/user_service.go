package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type userService struct {
	userRepo         repository.UserRepository
	authRepo         repository.AuthRepository
	patientRepo      repository.PatientProfileRepository
	consentRepo      repository.ConsentRepository
	notificationRepo repository.NotificationRepository
	sessionRepo      repository.SessionRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

func (s *userService) cacheAvailable() bool {
	return s != nil && s.cache != nil && s.cache.IsAvailable()
}

// NewUserService creates a new user service
func NewUserService(
	userRepo repository.UserRepository,
	authRepo repository.AuthRepository,
	patientRepo repository.PatientProfileRepository,
	consentRepo repository.ConsentRepository,
	notificationRepo repository.NotificationRepository,
	sessionRepo repository.SessionRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.UserService {
	return &userService{
		userRepo:         userRepo,
		authRepo:         authRepo,
		patientRepo:      patientRepo,
		consentRepo:      consentRepo,
		notificationRepo: notificationRepo,
		sessionRepo:      sessionRepo,
		cache:            cache,
		logger:           logger,
	}
}

// GetProfile gets user profile with additional info
func (s *userService) GetProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	return s.GetUserProfile(ctx, userID)
}

// GetUserByID gets user by ID
func (s *userService) GetUserByID(ctx context.Context, userID uuid.UUID) (core.User, error) {
	cacheKey := fmt.Sprintf("user:%s", userID.String())

	// Try cache first
	var user core.User
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &user); err == nil {
			s.logger.Debug().Str("user_id", userID.String()).Msg("User retrieved from cache")
			return user, nil
		}
	}

	// Fetch from database using user repo
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return core.User{}, domain.NewAppError(err, "User not found", 404)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, user, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache user")
		}
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

	// Update user fields based on updates map
	if email, ok := updates["email"].(string); ok && email != "" {
		// Validate email format
		if !strings.Contains(email, "@") {
			return domain.NewAppError(domain.ErrValidation, "Invalid email format", 400)
		}
		user.Email = &email
	}

	if phone, ok := updates["phone"].(string); ok && phone != "" {
		user.Phone = &phone
	}

	if role, ok := updates["role"].(string); ok && role != "" {
		user.Role = role
	}

	if status, ok := updates["status"].(string); ok && status != "" {
		user.Status = status
	}

	if smsOnly, ok := updates["is_sms_only"].(bool); ok {
		user.IsSMSOnly = smsOnly
	}

	if profilePct, ok := updates["profile_completion_pct"].(int); ok {
		user.ProfileCompletionPct = profilePct
	}

	// Update user in repository
	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Error().Err(err).Msg("Failed to update user")
		return domain.NewAppError(err, "Failed to update profile", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, userID)

	// Update patient profile if user is a patient
	if user.Role == "patient" {
		profile, err := s.patientRepo.GetPatientProfileByUserID(ctx, userID)
		if err != nil && !errors.Is(err, domain.ErrPatientNotFound) {
			s.logger.Error().Err(err).Msg("Failed to get patient profile")
			return domain.NewAppError(err, "Failed to update patient profile", 500)
		}
		// Update profile fields based on updates map
		s.updatePatientProfileFromMap(&profile, updates)
		if err := s.patientRepo.UpdatePatientProfile(ctx, profile); err != nil {
			s.logger.Error().Err(err).Msg("Failed to update patient profile")
			return domain.NewAppError(err, "Failed to update patient profile", 500)
		}
	}

	s.logger.Info().Str("user_id", userID.String()).Msg("User profile updated")
	return nil
}

// UpdatePassword updates user password
func (s *userService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	// Get user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return domain.NewAppError(err, "User not found", 404)
	}

	// Check if user has email or phone for authentication
	var passwordHash string
	if user.Email != nil && *user.Email != "" {
		// Get user with password hash by email
		_, passwordHash, err = s.authRepo.GetUserByEmail(ctx, *user.Email)
		if err != nil {
			return domain.NewAppError(err, "Failed to verify current password", 500)
		}
	} else if user.Phone != nil && *user.Phone != "" {
		// Get user with password hash by phone
		_, passwordHash, err = s.authRepo.GetUserByPhoneWithHash(ctx, *user.Phone)
		if err != nil {
			return domain.NewAppError(err, "Failed to verify current password", 500)
		}
	} else {
		return domain.NewAppError(nil, "User does not have email or phone set for authentication", 400)
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

	// Update password using auth repo
	if err := s.authRepo.UpdateUserPassword(ctx, userID, string(newHash)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to update password in database")
		return domain.NewAppError(err, "Failed to update password", 500)
	}

	// Invalidate all user sessions
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

	// Delete all sessions
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
func (s *userService) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	users, err := s.userRepo.ListUsers(ctx, role, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to list users")
		return nil, domain.NewAppError(err, "Failed to list users", 500)
	}

	return users, nil
}

// SearchUsers searches users with query, role, and status filters
func (s *userService) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	users, err := s.userRepo.SearchUsers(ctx, query, role, status)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to search users")
		return nil, domain.NewAppError(err, "Failed to search users", 500)
	}
	return users, nil
}

// GetConsent gets user consent settings
func (s *userService) GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error) {
	consent, err := s.consentRepo.GetPrivacyConsent(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get consent")
		return core.PrivacyConsent{}, domain.NewAppError(err, "Failed to get consent", 500)
	}

	return consent, nil
}

// UpdateConsent updates user consent settings
func (s *userService) UpdateConsent(ctx context.Context, userID uuid.UUID, consent core.PrivacyConsent) error {
	// Ensure the consent belongs to the user
	consent.UserID = userID
	consent.UpdatedAt = time.Now()

	if err := s.consentRepo.UpdatePrivacyConsent(ctx, consent); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update consent")
		return domain.NewAppError(err, "Failed to update consent", 500)
	}

	// Also update user's consent flags
	if err := s.userRepo.UpdateUserConsents(ctx, userID,
		consent.SMSCommunicationConsent,
		consent.HealthDataConsent,
		time.Now()); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to update user consent flags")
	}

	s.logger.Info().Str("user_id", userID.String()).Msg("Consent updated")
	return nil
}

// UpdateUserEmail updates user email
func (s *userService) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	if err := s.userRepo.UpdateUserEmail(ctx, id, email); err != nil {
		s.logger.Error().Err(err).Str("user_id", id.String()).Str("email", email).Msg("Failed to update user email")
		return domain.NewAppError(err, "Failed to update email", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, id)
	s.logger.Info().Str("user_id", id.String()).Msg("User email updated")
	return nil
}

// UpdateUserPhone updates user phone
func (s *userService) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	if err := s.userRepo.UpdateUserPhone(ctx, id, phone); err != nil {
		s.logger.Error().Err(err).Str("user_id", id.String()).Str("phone", phone).Msg("Failed to update user phone")
		return domain.NewAppError(err, "Failed to update phone", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, id)
	s.logger.Info().Str("user_id", id.String()).Msg("User phone updated")
	return nil
}

// UpdateUserRole updates user role
func (s *userService) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	if err := s.userRepo.UpdateUserRole(ctx, id, role); err != nil {
		s.logger.Error().Err(err).Str("user_id", id.String()).Str("role", role).Msg("Failed to update user role")
		return domain.NewAppError(err, "Failed to update role", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, id)
	s.logger.Info().Str("user_id", id.String()).Msg("User role updated")
	return nil
}

// UpdateUserStatus updates user status
func (s *userService) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	if err := s.userRepo.UpdateUserStatus(ctx, id, status); err != nil {
		s.logger.Error().Err(err).Str("user_id", id.String()).Str("status", status).Msg("Failed to update user status")
		return domain.NewAppError(err, "Failed to update status", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, id)
	s.logger.Info().Str("user_id", id.String()).Msg("User status updated")
	return nil
}

// UpdateUserProfileCompletion updates user profile completion percentage
func (s *userService) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	if err := s.userRepo.UpdateUserProfileCompletion(ctx, id, percentage); err != nil {
		s.logger.Error().Err(err).Str("user_id", id.String()).Int("percentage", percentage).Msg("Failed to update user profile completion")
		return domain.NewAppError(err, "Failed to update profile completion", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, id)
	s.logger.Info().Str("user_id", id.String()).Int("percentage", percentage).Msg("User profile completion updated")
	return nil
}

// UpdateUserConsents updates user consents
func (s *userService) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	if err := s.userRepo.UpdateUserConsents(ctx, id, smsConsent, popiaConsent, consentDate); err != nil {
		s.logger.Error().Err(err).Str("user_id", id.String()).Msg("Failed to update user consents")
		return domain.NewAppError(err, "Failed to update consents", 500)
	}

	// Invalidate cache
	s.invalidateUserCache(ctx, id)
	s.logger.Info().Str("user_id", id.String()).Msg("User consents updated")
	return nil
}

// BulkUpdateStatus updates status for multiple users
func (s *userService) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	if err := s.userRepo.BulkUpdateStatus(ctx, ids, status); err != nil {
		s.logger.Error().Err(err).Int("user_count", len(ids)).Str("status", status).Msg("Failed to bulk update user status")
		return domain.NewAppError(err, "Failed to bulk update status", 500)
	}

	// Invalidate cache for all users
	for _, id := range ids {
		s.invalidateUserCache(ctx, id)
	}

	s.logger.Info().Int("user_count", len(ids)).Str("status", status).Msg("Bulk user status updated")
	return nil
}

// GetUsersByIDs gets multiple users by their IDs
func (s *userService) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	users, err := s.userRepo.GetUsersByIDs(ctx, ids)
	if err != nil {
		s.logger.Error().Err(err).Int("user_count", len(ids)).Msg("Failed to get users by IDs")
		return nil, domain.NewAppError(err, "Failed to get users", 500)
	}
	return users, nil
}

// CountUsers counts users by role
func (s *userService) CountUsers(ctx context.Context, role string) (int64, error) {
	count, err := s.userRepo.CountUsers(ctx, role)
	if err != nil {
		s.logger.Error().Err(err).Str("role", role).Msg("Failed to count users")
		return 0, domain.NewAppError(err, "Failed to count users", 500)
	}
	return count, nil
}

// GetUserProfile gets user profile with patient profile (alias for GetProfile for interface compatibility)
func (s *userService) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	cacheKey := fmt.Sprintf("user:profile:%s", userID.String())

	// Try cache first
	type CachedProfile struct {
		User    core.User               `json:"user"`
		Profile patients.PatientProfile `json:"profile"`
	}
	var cached CachedProfile
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("user_id", userID.String()).Msg("Profile retrieved from cache")
			return cached.User, cached.Profile, nil
		}
	}

	// Get user from user repo
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return core.User{}, patients.PatientProfile{}, domain.NewAppError(err, "User not found", 404)
	}

	// Get patient profile if user is a patient
	var patientProfile patients.PatientProfile
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
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, cached, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache user profile")
		}
	}

	return user, patientProfile, nil
}

// Helper methods
func (s *userService) invalidateUserCache(ctx context.Context, userID uuid.UUID) {
	if !s.cacheAvailable() {
		return
	}

	cacheKeys := []string{
		fmt.Sprintf("user:%s", userID.String()),
		fmt.Sprintf("user:profile:%s", userID.String()),
		// Invalidate login caches too
		"user:login:*", // This would need pattern matching
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate cache")
		}
	}
}

func (s *userService) updatePatientProfileFromMap(profile *patients.PatientProfile, updates map[string]interface{}) {
	if firstName, ok := updates["first_name"].(string); ok {
		profile.FirstName = firstName
	}
	if lastName, ok := updates["last_name"].(string); ok {
		profile.LastName = lastName
	}
	if preferredName, ok := updates["preferred_name"].(string); ok {
		profile.PreferredName = &preferredName
	}
	if country, ok := updates["country"].(string); ok {
		profile.Country = country
	}
	profile.UpdatedAt = time.Now()
}
