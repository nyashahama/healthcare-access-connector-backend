package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type otpService struct {
	authRepo     repository.AuthRepository
	otpRepo      repository.OTPRepository
	emailService email.Service
	logger       *zerolog.Logger
	smsEnabled   bool
	bcryptCost   int
}

// NewOTPService creates a new OTP service
func NewOTPService(
	authRepo repository.AuthRepository,
	otpRepo repository.OTPRepository,
	emailService email.Service,
	logger *zerolog.Logger,
	smsEnabled bool,
	bcryptCost int,
) service.OTPService {
	return &otpService{
		authRepo:     authRepo,
		otpRepo:      otpRepo,
		emailService: emailService,
		logger:       logger,
		smsEnabled:   smsEnabled,
		bcryptCost:   bcryptCost,
	}
}

// GenerateOTP generates and sends OTP to user
func (s *otpService) GenerateOTP(ctx context.Context, identifier string) error {
	// Find user by email or phone
	var user core.User
	var err error
	channel := "email"

	if strings.Contains(identifier, "@") {
		user, _, err = s.authRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
	} else {
		user, _, err = s.authRepo.GetUserByPhoneWithHash(ctx, identifier)
		channel = "sms"
	}

	if err != nil {
		// Don't reveal if user exists for security
		s.logger.Info().Str("identifier", maskIdentifier(identifier)).Msg("OTP requested for non-existent user")
		return nil
	}

	// Check OTP attempt count (rate limiting)
	attempts, err := s.otpRepo.GetOTPAttemptCount(ctx, user.ID, "password_reset")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to get OTP attempt count")
	}
	if attempts >= 5 {
		return domain.NewAppError(domain.ErrOTPRateLimited, "Too many OTP requests. Please try again later.", 429)
	}

	// Check if user can receive OTP
	if channel == "email" && (user.Email == nil || *user.Email == "") {
		s.logger.Warn().Str("user_id", user.ID.String()).Msg("User cannot receive email OTP")
		return nil
	}
	if channel == "sms" && (user.Phone == nil || *user.Phone == "" || !user.SMSConsentGiven) {
		s.logger.Warn().Str("user_id", user.ID.String()).Msg("User cannot receive SMS OTP")
		return nil
	}

	// Generate 6-digit OTP
	otp := s.generateNumericOTP(6)
	expiresAt := time.Now().Add(10 * time.Minute)

	// Delete any existing unused OTPs for this user
	if err := s.otpRepo.DeleteUserOTPs(ctx, user.ID, "password_reset"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete old OTPs")
	}

	// Create OTP record
	otpRecord := core.OTPVerification{
		ID:        uuid.New(),
		UserID:    user.ID,
		OTP:       otp,
		Type:      "password_reset",
		Channel:   channel,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	// Save OTP to repository
	if err := s.otpRepo.SaveOTP(ctx, otpRecord); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save OTP")
		return domain.NewAppError(err, "Failed to generate OTP", 500)
	}

	// Send OTP via email or SMS
	if channel == "email" && user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		if err := s.emailService.SendOTPEmail(ctx, *user.Email, otp, user.ID.String()); err != nil {
			s.logger.Error().Err(err).Msg("Failed to send OTP email")
			return domain.NewAppError(err, "Failed to send OTP email", 500)
		}
	} else if channel == "sms" && user.Phone != nil && s.smsEnabled {
		// TODO: Implement SMS sending for OTP
		s.logger.Info().
			Str("phone", maskIdentifier(*user.Phone)).
			Str("otp", otp).
			Msg("OTP generated for SMS (SMS service not implemented)")
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("channel", channel).
		Msg("OTP generated and sent")

	return nil
}

// VerifyOTP verifies OTP and returns reset token
func (s *otpService) VerifyOTP(ctx context.Context, identifier, otp string) (string, error) {
	// Find user
	var user core.User
	var err error

	if strings.Contains(identifier, "@") {
		user, _, err = s.authRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
	} else {
		user, _, err = s.authRepo.GetUserByPhoneWithHash(ctx, identifier)
	}

	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", domain.NewAppError(domain.ErrInvalidOTP, "Invalid OTP code", 400)
		}
		return "", domain.NewAppError(err, "OTP verification failed", 500)
	}

	// Get OTP record
	otpRecord, err := s.otpRepo.GetOTP(ctx, user.ID, otp, "password_reset")
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Warn().
				Str("user_id", user.ID.String()).
				Str("identifier", maskIdentifier(identifier)).
				Msg("Invalid OTP attempt")
			return "", domain.NewAppError(domain.ErrInvalidOTP, "Invalid OTP code", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get OTP")
		return "", domain.NewAppError(err, "OTP verification failed", 500)
	}

	// Check if OTP is expired
	if time.Now().After(otpRecord.ExpiresAt) {
		return "", domain.NewAppError(domain.ErrOTPExpired, "OTP has expired", 400)
	}

	// Check if OTP already used
	if otpRecord.UsedAt != nil {
		return "", domain.NewAppError(domain.ErrOTPAlreadyUsed, "OTP has already been used", 400)
	}

	// Mark OTP as used
	now := time.Now()
	if err := s.otpRepo.MarkOTPUsed(ctx, otpRecord.ID, &now); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to mark OTP as used")
	}

	// Generate password reset token
	resetToken := s.generateSecureToken()
	tokenExpires := time.Now().Add(1 * time.Hour)

	// Store reset token
	if err := s.authRepo.SetPasswordResetToken(ctx, user.ID, resetToken, tokenExpires); err != nil {
		s.logger.Error().Err(err).Msg("Failed to set password reset token")
		return "", domain.NewAppError(err, "Failed to process reset", 500)
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Msg("OTP verified successfully")

	return resetToken, nil
}

// ResetPasswordWithOTP combines OTP verification and password reset
func (s *otpService) ResetPasswordWithOTP(ctx context.Context, identifier, otp, newPassword string) error {
	// Verify OTP first
	resetToken, err := s.VerifyOTP(ctx, identifier, otp)
	if err != nil {
		return err
	}

	// Now reset password using the token
	return s.resetPasswordWithToken(ctx, resetToken, newPassword)
}

// GetLatestActiveOTP gets the latest active OTP for a user
func (s *otpService) GetLatestActiveOTP(ctx context.Context, userID uuid.UUID, otpType string) (core.OTPVerification, error) {
	otp, err := s.otpRepo.GetLatestActiveOTP(ctx, userID, otpType)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return core.OTPVerification{}, domain.NewAppError(domain.ErrNotFound, "No active OTP found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Str("type", otpType).Msg("Failed to get latest active OTP")
		return core.OTPVerification{}, domain.NewAppError(err, "Failed to get OTP", 500)
	}
	return otp, nil
}

// InvalidateUserOTPs invalidates all OTPs for a user
func (s *otpService) InvalidateUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	if err := s.otpRepo.InvalidateUserOTPs(ctx, userID, otpType); err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Str("type", otpType).Msg("Failed to invalidate user OTPs")
		return domain.NewAppError(err, "Failed to invalidate OTPs", 500)
	}
	s.logger.Info().Str("user_id", userID.String()).Str("type", otpType).Msg("User OTPs invalidated")
	return nil
}

// DeleteExpiredOTPs deletes all expired OTPs
func (s *otpService) DeleteExpiredOTPs(ctx context.Context) error {
	if err := s.otpRepo.DeleteExpiredOTPs(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Failed to delete expired OTPs")
		return domain.NewAppError(err, "Failed to delete expired OTPs", 500)
	}
	s.logger.Info().Msg("Expired OTPs deleted")
	return nil
}

// GetOTPAttemptCount gets OTP attempt count for a user
func (s *otpService) GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
	count, err := s.otpRepo.GetOTPAttemptCount(ctx, userID, otpType)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Str("type", otpType).Msg("Failed to get OTP attempt count")
		return 0, domain.NewAppError(err, "Failed to get OTP attempt count", 500)
	}
	return count, nil
}

// GetRecentOTPs gets recent OTPs for a user within a time period
func (s *otpService) GetRecentOTPs(ctx context.Context, userID uuid.UUID, within time.Duration) ([]core.OTPVerification, error) {
	otps, err := s.otpRepo.GetRecentOTPs(ctx, userID, within)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get recent OTPs")
		return nil, domain.NewAppError(err, "Failed to get recent OTPs", 500)
	}
	return otps, nil
}

// Helper method to reset password with token
func (s *otpService) resetPasswordWithToken(ctx context.Context, token, newPassword string) error {
	user, _, err := s.authRepo.GetUserByPasswordResetToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrInvalidToken, "Invalid or expired reset token", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get user by reset token")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash new password")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Update password
	if err := s.authRepo.UpdateUserPassword(ctx, user.ID, string(hash)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to update password")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	s.logger.Info().Str("user_id", user.ID.String()).Msg("Password reset successfully with OTP")
	return nil
}

// Helper functions
func (s *otpService) generateNumericOTP(length int) string {
	const digits = "0123456789"
	b := make([]byte, length)
	rand.Read(b)

	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}

	return string(b)
}

func (s *otpService) generateSecureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
