package core

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	domaincore "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type otpTestAuthRepository struct {
	getUserByEmailFunc          func(ctx context.Context, email string) (domaincore.User, string, error)
	getUserByPhoneWithHashFunc  func(ctx context.Context, phone string) (domaincore.User, string, error)
	setPasswordResetTokenFunc   func(ctx context.Context, id uuid.UUID, token string, expires time.Time) error
}

func (m *otpTestAuthRepository) CreateUser(ctx context.Context, user domaincore.User, passwordHash string) (domaincore.User, error) {
	return domaincore.User{}, nil
}
func (m *otpTestAuthRepository) GetUserByEmail(ctx context.Context, email string) (domaincore.User, string, error) {
	if m.getUserByEmailFunc != nil {
		return m.getUserByEmailFunc(ctx, email)
	}
	return domaincore.User{}, "", domain.ErrUserNotFound
}
func (m *otpTestAuthRepository) GetUserByPhone(ctx context.Context, phone string) (domaincore.User, error) {
	return domaincore.User{}, domain.ErrUserNotFound
}
func (m *otpTestAuthRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (domaincore.User, string, error) {
	if m.getUserByPhoneWithHashFunc != nil {
		return m.getUserByPhoneWithHashFunc(ctx, phone)
	}
	return domaincore.User{}, "", domain.ErrUserNotFound
}
func (m *otpTestAuthRepository) GetUserByVerificationToken(ctx context.Context, token string) (domaincore.User, string, error) {
	return domaincore.User{}, "", domain.ErrUserNotFound
}
func (m *otpTestAuthRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (domaincore.User, string, error) {
	return domaincore.User{}, "", domain.ErrUserNotFound
}
func (m *otpTestAuthRepository) SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	return nil
}
func (m *otpTestAuthRepository) SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	if m.setPasswordResetTokenFunc != nil {
		return m.setPasswordResetTokenFunc(ctx, id, token, expires)
	}
	return nil
}
func (m *otpTestAuthRepository) VerifyUser(ctx context.Context, id uuid.UUID) error { return nil }
func (m *otpTestAuthRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return nil
}
func (m *otpTestAuthRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error { return nil }
func (m *otpTestAuthRepository) UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error {
	return nil
}
func (m *otpTestAuthRepository) UpdateUserPrimaryClinic(ctx context.Context, userID uuid.UUID, clinicID uuid.UUID) error {
	return nil
}
func (m *otpTestAuthRepository) CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *otpTestAuthRepository) GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*domaincore.ProviderWithClinic, error) {
	return nil, nil
}
func (m *otpTestAuthRepository) GetUserClinics(ctx context.Context, userID uuid.UUID) ([]domaincore.UserClinic, error) {
	return nil, nil
}

type otpTestOTPRepository struct {
	getOTPAttemptCountFunc func(ctx context.Context, userID uuid.UUID, otpType string) (int64, error)
	deleteUserOTPsFunc     func(ctx context.Context, userID uuid.UUID, otpType string) error
	saveOTPFunc            func(ctx context.Context, otp domaincore.OTPVerification) error
	getOTPFunc             func(ctx context.Context, userID uuid.UUID, otp, otpType string) (domaincore.OTPVerification, error)
	markOTPUsedFunc        func(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error
}

func (m *otpTestOTPRepository) SaveOTP(ctx context.Context, otp domaincore.OTPVerification) error {
	if m.saveOTPFunc != nil {
		return m.saveOTPFunc(ctx, otp)
	}
	return nil
}
func (m *otpTestOTPRepository) GetOTP(ctx context.Context, userID uuid.UUID, otp, otpType string) (domaincore.OTPVerification, error) {
	if m.getOTPFunc != nil {
		return m.getOTPFunc(ctx, userID, otp, otpType)
	}
	return domaincore.OTPVerification{}, domain.ErrNotFound
}
func (m *otpTestOTPRepository) GetLatestActiveOTP(ctx context.Context, userID uuid.UUID, otpType string) (domaincore.OTPVerification, error) {
	return domaincore.OTPVerification{}, domain.ErrNotFound
}
func (m *otpTestOTPRepository) MarkOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error {
	if m.markOTPUsedFunc != nil {
		return m.markOTPUsedFunc(ctx, otpID, usedAt)
	}
	return nil
}
func (m *otpTestOTPRepository) InvalidateUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	return nil
}
func (m *otpTestOTPRepository) DeleteExpiredOTPs(ctx context.Context) error { return nil }
func (m *otpTestOTPRepository) DeleteUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	if m.deleteUserOTPsFunc != nil {
		return m.deleteUserOTPsFunc(ctx, userID, otpType)
	}
	return nil
}
func (m *otpTestOTPRepository) GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
	if m.getOTPAttemptCountFunc != nil {
		return m.getOTPAttemptCountFunc(ctx, userID, otpType)
	}
	return 0, nil
}
func (m *otpTestOTPRepository) GetRecentOTPs(ctx context.Context, userID uuid.UUID, within time.Duration) ([]domaincore.OTPVerification, error) {
	return nil, nil
}

type otpTestEmailService struct {
	available       bool
	sendOTPEmailFunc func(ctx context.Context, email, otp, userID string) error
}

func (m *otpTestEmailService) Send(ctx context.Context, msg *emailtypes.Message, callback func(error)) error {
	return nil
}
func (m *otpTestEmailService) SendSync(ctx context.Context, msg *emailtypes.Message) error { return nil }
func (m *otpTestEmailService) SendWelcomeEmail(ctx context.Context, to, username string) error { return nil }
func (m *otpTestEmailService) SendOTPEmail(ctx context.Context, email, otp, userID string) error {
	if m.sendOTPEmailFunc != nil {
		return m.sendOTPEmailFunc(ctx, email, otp, userID)
	}
	return nil
}
func (m *otpTestEmailService) SendPasswordResetEmail(ctx context.Context, to, resetToken string) error {
	return nil
}
func (m *otpTestEmailService) SendVerificationEmail(ctx context.Context, to, verificationToken string) error {
	return nil
}
func (m *otpTestEmailService) SendPasswordChangedEmail(ctx context.Context, to, username string) error {
	return nil
}
func (m *otpTestEmailService) SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error {
	return nil
}
func (m *otpTestEmailService) SendStaffInvitationEmail(ctx context.Context, to, firstName, lastName, clinicName, invitationToken string) error {
	return nil
}
func (m *otpTestEmailService) HealthCheck(ctx context.Context) error { return nil }
func (m *otpTestEmailService) GetStats() map[string]interface{} { return nil }
func (m *otpTestEmailService) GetHealthStatus() map[string]interface{} { return nil }
func (m *otpTestEmailService) IsAvailable() bool { return m.available }
func (m *otpTestEmailService) Close() error { return nil }

type otpTestSMSSender struct {
	available   bool
	sendOTPFunc func(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error)
}

func (m *otpTestSMSSender) IsAvailable() bool { return m.available }
func (m *otpTestSMSSender) SendOTP(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error) {
	if m.sendOTPFunc != nil {
		return m.sendOTPFunc(ctx, phoneNumber, otp)
	}
	return &otpSMSDelivery{
		MessageBody: "Your Healthcare Access Connector verification code is 123456. It expires in 10 minutes.",
		Segments:    1,
	}, nil
}

var _ repository.AuthRepository = (*otpTestAuthRepository)(nil)
var _ repository.OTPRepository = (*otpTestOTPRepository)(nil)

func TestGenerateOTPPhoneUserSendsSMSWhenConfigured(t *testing.T) {
	logger := zerolog.New(io.Discard)
	user := domaincore.User{
		ID:              uuid.New(),
		Phone:           otpStringPtr("+27710000000"),
		SMSConsentGiven: true,
	}

	authRepo := &otpTestAuthRepository{
		getUserByPhoneWithHashFunc: func(ctx context.Context, phone string) (domaincore.User, string, error) {
			return user, "hash", nil
		},
	}

	var savedOTP domaincore.OTPVerification
	otpRepo := &otpTestOTPRepository{
		getOTPAttemptCountFunc: func(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
			return 0, nil
		},
		deleteUserOTPsFunc: func(ctx context.Context, userID uuid.UUID, otpType string) error { return nil },
		saveOTPFunc: func(ctx context.Context, otp domaincore.OTPVerification) error {
			savedOTP = otp
			return nil
		},
	}

	var sentPhone string
	smsSender := &otpTestSMSSender{
		available: true,
		sendOTPFunc: func(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error) {
			sentPhone = phoneNumber
			assert.Len(t, otp, 6)
			return &otpSMSDelivery{
				MessageBody: "Your Healthcare Access Connector verification code is " + otp + ". It expires in 10 minutes.",
				Segments:    1,
			}, nil
		},
	}

	svc := newOTPService(authRepo, otpRepo, nil, nil, &logger, true, 4, smsSender)

	channel, err := svc.GenerateOTP(context.Background(), *user.Phone)
	require.NoError(t, err)
	assert.Equal(t, "sms", channel)
	assert.Equal(t, "sms", savedOTP.Channel)
	assert.Equal(t, *user.Phone, sentPhone)
}

func TestGenerateOTPPhoneUserFallsBackToEmailWhenSMSUnavailable(t *testing.T) {
	logger := zerolog.New(io.Discard)
	user := domaincore.User{
		ID:              uuid.New(),
		Phone:           otpStringPtr("+27710000001"),
		Email:           otpStringPtr("user@example.com"),
		SMSConsentGiven: true,
	}

	authRepo := &otpTestAuthRepository{
		getUserByPhoneWithHashFunc: func(ctx context.Context, phone string) (domaincore.User, string, error) {
			return user, "hash", nil
		},
	}

	otpRepo := &otpTestOTPRepository{
		getOTPAttemptCountFunc: func(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
			return 0, nil
		},
		deleteUserOTPsFunc: func(ctx context.Context, userID uuid.UUID, otpType string) error { return nil },
		saveOTPFunc: func(ctx context.Context, otp domaincore.OTPVerification) error {
			assert.Equal(t, "email", otp.Channel)
			return nil
		},
	}

	var emailedTo string
	emailSvc := &otpTestEmailService{
		available: true,
		sendOTPEmailFunc: func(ctx context.Context, email, otp, userID string) error {
			emailedTo = email
			return nil
		},
	}

	svc := newOTPService(authRepo, otpRepo, emailSvc, nil, &logger, true, 4, nil)

	channel, err := svc.GenerateOTP(context.Background(), *user.Phone)
	require.NoError(t, err)
	assert.Equal(t, "email", channel)
	assert.Equal(t, *user.Email, emailedTo)
}

func TestGenerateOTPDeletesSavedOTPWhenSMSSendFails(t *testing.T) {
	logger := zerolog.New(io.Discard)
	user := domaincore.User{
		ID:              uuid.New(),
		Phone:           otpStringPtr("+27710000002"),
		SMSConsentGiven: true,
	}

	authRepo := &otpTestAuthRepository{
		getUserByPhoneWithHashFunc: func(ctx context.Context, phone string) (domaincore.User, string, error) {
			return user, "hash", nil
		},
	}

	var deleted bool
	otpRepo := &otpTestOTPRepository{
		getOTPAttemptCountFunc: func(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
			return 0, nil
		},
		deleteUserOTPsFunc: func(ctx context.Context, userID uuid.UUID, otpType string) error {
			deleted = true
			return nil
		},
		saveOTPFunc: func(ctx context.Context, otp domaincore.OTPVerification) error { return nil },
	}

	smsSender := &otpTestSMSSender{
		available: true,
		sendOTPFunc: func(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error) {
			return nil, errors.New("twilio down")
		},
	}

	svc := newOTPService(authRepo, otpRepo, nil, nil, &logger, true, 4, smsSender)

	_, err := svc.GenerateOTP(context.Background(), *user.Phone)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to send OTP SMS")
	assert.True(t, deleted)
}

func otpStringPtr(value string) *string {
	return &value
}
