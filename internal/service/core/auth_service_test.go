package core

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func generateValidJWT(t *testing.T, userID uuid.UUID, secret string, expiry time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"email":   "user@example.com",
		"role":    "patient",
		"exp":     expiry.Unix(),
		"iat":     time.Now().Unix(),
		"iss":     "healthcare-access-connector",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return signedToken
}

type mockAuthRepository struct {
	getUserByEmailFunc              func(ctx context.Context, email string) (core.User, string, error)
	getUserByVerificationTokenFunc  func(ctx context.Context, token string) (core.User, string, error)
	getUserByPasswordResetTokenFunc func(ctx context.Context, token string) (core.User, string, error)
	setVerificationTokenFunc        func(ctx context.Context, id uuid.UUID, token string, expires time.Time) error
	setPasswordResetTokenFunc       func(ctx context.Context, id uuid.UUID, token string, expires time.Time) error
	verifyUserFunc                  func(ctx context.Context, id uuid.UUID) error
	updateUserPasswordFunc          func(ctx context.Context, id uuid.UUID, passwordHash string) error
	updateLastLoginFunc             func(ctx context.Context, id uuid.UUID) error
}

func (m *mockAuthRepository) CreateUser(ctx context.Context, user core.User, passwordHash string) (core.User, error) {
	return core.User{}, nil
}

func (m *mockAuthRepository) GetUserByEmail(ctx context.Context, email string) (core.User, string, error) {
	if m.getUserByEmailFunc != nil {
		return m.getUserByEmailFunc(ctx, email)
	}
	return core.User{}, "", domain.ErrUserNotFound
}

func (m *mockAuthRepository) GetUserByPhone(ctx context.Context, phone string) (core.User, error) {
	return core.User{}, domain.ErrUserNotFound
}

func (m *mockAuthRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (core.User, string, error) {
	return core.User{}, "", domain.ErrUserNotFound
}

func (m *mockAuthRepository) GetUserByVerificationToken(ctx context.Context, token string) (core.User, string, error) {
	if m.getUserByVerificationTokenFunc != nil {
		return m.getUserByVerificationTokenFunc(ctx, token)
	}
	return core.User{}, "", domain.ErrUserNotFound
}

func (m *mockAuthRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (core.User, string, error) {
	if m.getUserByPasswordResetTokenFunc != nil {
		return m.getUserByPasswordResetTokenFunc(ctx, token)
	}
	return core.User{}, "", domain.ErrUserNotFound
}

func (m *mockAuthRepository) SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	if m.setVerificationTokenFunc != nil {
		return m.setVerificationTokenFunc(ctx, id, token, expires)
	}
	return nil
}

func (m *mockAuthRepository) SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	if m.setPasswordResetTokenFunc != nil {
		return m.setPasswordResetTokenFunc(ctx, id, token, expires)
	}
	return nil
}

func (m *mockAuthRepository) VerifyUser(ctx context.Context, id uuid.UUID) error {
	if m.verifyUserFunc != nil {
		return m.verifyUserFunc(ctx, id)
	}
	return nil
}

func (m *mockAuthRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	if m.updateUserPasswordFunc != nil {
		return m.updateUserPasswordFunc(ctx, id, passwordHash)
	}
	return nil
}

func (m *mockAuthRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	if m.updateLastLoginFunc != nil {
		return m.updateLastLoginFunc(ctx, id)
	}
	return nil
}

func (m *mockAuthRepository) UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error {
	return nil
}

func (m *mockAuthRepository) UpdateUserPrimaryClinic(ctx context.Context, userID uuid.UUID, clinicID uuid.UUID) error {
	return nil
}

func (m *mockAuthRepository) CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockAuthRepository) GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error) {
	return nil, nil
}

func (m *mockAuthRepository) GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error) {
	return nil, nil
}

type mockUserRepository struct {
	getUserByIDFunc      func(ctx context.Context, id uuid.UUID) (core.User, error)
	updateUserStatusFunc func(ctx context.Context, id uuid.UUID, status string) error
}

func (m *mockUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	if m.getUserByIDFunc != nil {
		return m.getUserByIDFunc(ctx, id)
	}
	return core.User{}, domain.ErrUserNotFound
}

func (m *mockUserRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	if m.updateUserStatusFunc != nil {
		return m.updateUserStatusFunc(ctx, id, status)
	}
	return nil
}

func (m *mockUserRepository) UpdateUser(ctx context.Context, user core.User) error {
	return nil
}

func (m *mockUserRepository) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepository) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepository) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepository) CountUsers(ctx context.Context, role string) (int64, error) {
	return 0, nil
}

func (m *mockUserRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	return core.User{}, patients.PatientProfile{}, nil
}

func (m *mockUserRepository) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	return nil
}

func (m *mockUserRepository) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	return nil
}

func (m *mockUserRepository) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	return nil
}

func (m *mockUserRepository) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	return nil
}

func (m *mockUserRepository) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	return nil
}

func (m *mockUserRepository) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepository) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	return nil, nil
}

type mockSessionService struct {
	createSessionFunc     func(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time, ipAddress, userAgent, deviceType string) (core.UserSession, error)
	getSessionFunc        func(ctx context.Context, token string) (core.UserSession, error)
	revokeSessionFunc     func(ctx context.Context, token string, userID uuid.UUID) error
	revokeAllSessionsFunc func(ctx context.Context, userID uuid.UUID) error
}

func (m *mockSessionService) CreateSession(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time, ipAddress, userAgent, deviceType string) (core.UserSession, error) {
	if m.createSessionFunc != nil {
		return m.createSessionFunc(ctx, userID, token, expiresAt, ipAddress, userAgent, deviceType)
	}
	return core.UserSession{}, nil
}

func (m *mockSessionService) GetSession(ctx context.Context, token string) (core.UserSession, error) {
	if m.getSessionFunc != nil {
		return m.getSessionFunc(ctx, token)
	}
	return core.UserSession{}, domain.ErrInvalidSession
}

func (m *mockSessionService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]core.UserSession, error) {
	return nil, nil
}

func (m *mockSessionService) RevokeSession(ctx context.Context, token string, userID uuid.UUID) error {
	if m.revokeSessionFunc != nil {
		return m.revokeSessionFunc(ctx, token, userID)
	}
	return nil
}

func (m *mockSessionService) RevokeAllSessions(ctx context.Context, userID uuid.UUID) error {
	if m.revokeAllSessionsFunc != nil {
		return m.revokeAllSessionsFunc(ctx, userID)
	}
	return nil
}

func (m *mockSessionService) RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID uuid.UUID) error {
	return nil
}

func (m *mockSessionService) InvalidateSessionByDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	return nil
}

func (m *mockSessionService) UpdateSessionToken(ctx context.Context, sessionID uuid.UUID, newToken string, expiresAt time.Time) error {
	return nil
}

func (m *mockSessionService) CleanupExpiredSessions(ctx context.Context) error {
	return nil
}

func (m *mockSessionService) GetActiveSessionCount(ctx context.Context, userID uuid.UUID) (int, error) {
	return 0, nil
}

func (m *mockSessionService) ValidateAndExtendSession(ctx context.Context, token string, extendDuration time.Duration) (core.UserSession, error) {
	return core.UserSession{}, nil
}

func (m *mockSessionService) StartSessionCleanupJob(interval time.Duration) {}

type mockEmailService struct {
	available                    bool
	sendWelcomeEmailFunc         func(ctx context.Context, to, username string) error
	sendPasswordResetEmailFunc   func(ctx context.Context, to, resetToken string) error
	sendPasswordChangedEmailFunc func(ctx context.Context, to, username string) error
	sendVerificationEmailFunc    func(ctx context.Context, to, verificationToken string) error
	sendStaffInvitationEmailFunc func(ctx context.Context, to, firstName, lastName, clinicName, invitationToken string) error
	sendLoginAlertEmailFunc      func(ctx context.Context, to, username, ipAddress, location string) error
}

func (m *mockEmailService) Send(ctx context.Context, msg *types.Message, callback func(error)) error {
	return nil
}

func (m *mockEmailService) SendSync(ctx context.Context, msg *types.Message) error {
	return nil
}

func (m *mockEmailService) SendWelcomeEmail(ctx context.Context, to, username string) error {
	if m.sendWelcomeEmailFunc != nil {
		return m.sendWelcomeEmailFunc(ctx, to, username)
	}
	return nil
}

func (m *mockEmailService) SendOTPEmail(ctx context.Context, email, otp, userID string) error {
	return nil
}

func (m *mockEmailService) SendPasswordResetEmail(ctx context.Context, to, resetToken string) error {
	if m.sendPasswordResetEmailFunc != nil {
		return m.sendPasswordResetEmailFunc(ctx, to, resetToken)
	}
	return nil
}

func (m *mockEmailService) SendVerificationEmail(ctx context.Context, to, verificationToken string) error {
	if m.sendVerificationEmailFunc != nil {
		return m.sendVerificationEmailFunc(ctx, to, verificationToken)
	}
	return nil
}

func (m *mockEmailService) SendStaffInvitationEmail(
	ctx context.Context,
	to, firstName, lastName, clinicName, invitationToken string,
) error {
	if m.sendStaffInvitationEmailFunc != nil {
		return m.sendStaffInvitationEmailFunc(ctx, to, firstName, lastName, clinicName, invitationToken)
	}
	return nil
}

func (m *mockEmailService) SendPasswordChangedEmail(ctx context.Context, to, username string) error {
	if m.sendPasswordChangedEmailFunc != nil {
		return m.sendPasswordChangedEmailFunc(ctx, to, username)
	}
	return nil
}

func (m *mockEmailService) SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error {
	if m.sendLoginAlertEmailFunc != nil {
		return m.sendLoginAlertEmailFunc(ctx, to, username, ipAddress, location)
	}
	return nil
}

func (m *mockEmailService) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockEmailService) GetStats() map[string]interface{} {
	return nil
}

func (m *mockEmailService) GetHealthStatus() map[string]interface{} {
	return nil
}

func (m *mockEmailService) IsAvailable() bool {
	return m.available
}

func (m *mockEmailService) Close() error {
	return nil
}

func newAuthServiceForTest(t *testing.T, maxAttempts int, lockout time.Duration) *authService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &authService{
		logger:           &logger,
		jwtSecret:        strings.Repeat("x", 32),
		jwtExpiry:        time.Hour,
		bcryptCost:       bcrypt.MinCost,
		loginAttempts:    make(map[string]loginAttempt),
		loginMaxAttempts: maxAttempts,
		loginLockout:     lockout,
		tokenPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32)
			},
		},
	}
}

func newAuthServiceWithMocks(t *testing.T, maxAttempts int, lockout time.Duration) (*authService, *mockAuthRepository, *mockUserRepository, *mockSessionService) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockAuthRepo := &mockAuthRepository{}
	mockUserRepo := &mockUserRepository{}
	mockSessionSvc := &mockSessionService{}
	mockEmailSvc := &mockEmailService{available: true}

	return &authService{
		authRepo:         mockAuthRepo,
		userRepo:         mockUserRepo,
		sessionSvc:       mockSessionSvc,
		emailService:     mockEmailSvc,
		logger:           &logger,
		jwtSecret:        strings.Repeat("x", 32),
		jwtExpiry:        time.Hour,
		bcryptCost:       bcrypt.MinCost,
		loginAttempts:    make(map[string]loginAttempt),
		loginMaxAttempts: maxAttempts,
		loginLockout:     lockout,
		tokenPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32)
			},
		},
	}, mockAuthRepo, mockUserRepo, mockSessionSvc
}

func TestRegisterRejectsPrivilegedSelfSelection(t *testing.T) {
	svc := newAuthServiceForTest(t, 5, 5*time.Minute)
	_, err := svc.Register(context.Background(), "admin@example.com", "", "StrongPass123!", "system_admin")
	require.Error(t, err)
}

func TestRecordFailedLoginUsesConfiguredThresholds(t *testing.T) {
	svc := newAuthServiceForTest(t, 3, 2*time.Minute)
	svc.recordFailedLogin("user@example.com")
	svc.recordFailedLogin("user@example.com")
	svc.recordFailedLogin("user@example.com")
	assert.True(t, svc.isLoginLocked("user@example.com"))
}

func TestLoginSuccess(t *testing.T) {
	svc, mockAuth, _, mockSession := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	testUser := core.User{
		ID:         uuid.New(),
		Email:      stringPtr("user@example.com"),
		Role:       "patient",
		Status:     "active",
		IsVerified: true,
	}
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)

	mockAuth.getUserByEmailFunc = func(ctx context.Context, email string) (core.User, string, error) {
		return testUser, string(passwordHash), nil
	}

	mockSession.createSessionFunc = func(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time, ipAddress, userAgent, deviceType string) (core.UserSession, error) {
		return core.UserSession{ID: uuid.New(), UserID: userID}, nil
	}

	token, expiresAt, user, err := svc.Login(context.Background(), "user@example.com", "password123", "127.0.0.1", "Mozilla")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, expiresAt.After(time.Now()))
	assert.Equal(t, testUser.ID, user.ID)
}

func TestLoginInvalidPassword(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	testUser := core.User{
		ID:         uuid.New(),
		Email:      stringPtr("user@example.com"),
		Role:       "patient",
		Status:     "active",
		IsVerified: true,
	}
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.MinCost)

	mockAuth.getUserByEmailFunc = func(ctx context.Context, email string) (core.User, string, error) {
		return testUser, string(passwordHash), nil
	}

	_, _, _, err := svc.Login(context.Background(), "user@example.com", "wrongpassword", "127.0.0.1", "Mozilla")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid credentials")
}

func TestLoginUserNotFound(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	mockAuth.getUserByEmailFunc = func(ctx context.Context, email string) (core.User, string, error) {
		return core.User{}, "", domain.ErrUserNotFound
	}

	_, _, _, err := svc.Login(context.Background(), "nonexistent@example.com", "password123", "127.0.0.1", "Mozilla")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid credentials")
}

func TestLoginAccountLocked(t *testing.T) {
	svc := newAuthServiceForTest(t, 3, 5*time.Minute)

	svc.recordFailedLogin("user@example.com")
	svc.recordFailedLogin("user@example.com")
	svc.recordFailedLogin("user@example.com")

	assert.True(t, svc.isLoginLocked("user@example.com"))

	_, _, _, err := svc.Login(context.Background(), "user@example.com", "password123", "127.0.0.1", "Mozilla")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Too many login attempts")
}

func TestRefreshTokenSuccess(t *testing.T) {
	svc, _, mockUserRepo, mockSession := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	testUser := core.User{
		ID:         uuid.New(),
		Email:      stringPtr("user@example.com"),
		Role:       "patient",
		Status:     "active",
		IsVerified: true,
	}

	validToken := generateValidJWT(t, testUser.ID, strings.Repeat("x", 32), time.Now().Add(time.Hour))

	mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
		return testUser, nil
	}

	mockSession.getSessionFunc = func(ctx context.Context, token string) (core.UserSession, error) {
		return core.UserSession{ID: uuid.New(), UserID: testUser.ID, ExpiresAt: time.Now().Add(time.Hour)}, nil
	}

	mockSession.revokeSessionFunc = func(ctx context.Context, token string, userID uuid.UUID) error {
		return nil
	}

	mockSession.createSessionFunc = func(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time, ipAddress, userAgent, deviceType string) (core.UserSession, error) {
		return core.UserSession{ID: uuid.New(), UserID: userID}, nil
	}

	token, expiresAt, user, err := svc.RefreshToken(context.Background(), validToken, "127.0.0.1", "Mozilla")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, expiresAt.After(time.Now()))
	assert.Equal(t, testUser.ID, user.ID)
}

func TestRefreshTokenExpired(t *testing.T) {
	svc, _, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	invalidToken := "invalid.jwt.token"

	_, _, _, err := svc.RefreshToken(context.Background(), invalidToken, "127.0.0.1", "Mozilla")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid")
}

func TestRefreshTokenInvalidSignature(t *testing.T) {
	svc, _, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	claims := jwt.MapClaims{
		"user_id": uuid.New().String(),
		"email":   "user@example.com",
		"role":    "patient",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
		"iss":     "healthcare-access-connector",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	invalidToken, _ := token.SignedString([]byte("wrong-secret"))

	_, _, _, err := svc.RefreshToken(context.Background(), invalidToken, "127.0.0.1", "Mozilla")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid token")
}

func TestLogoutSuccess(t *testing.T) {
	svc, _, _, mockSession := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	userID := uuid.New()

	mockSession.revokeSessionFunc = func(ctx context.Context, token string, userID uuid.UUID) error {
		return nil
	}

	err := svc.Logout(context.Background(), "valid-token", userID)
	require.NoError(t, err)
}

func TestVerifyEmailSuccess(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	testUser := core.User{
		ID:                  uuid.New(),
		Email:               stringPtr("user@example.com"),
		IsVerified:          false,
		VerificationExpires: func() *time.Time { t := time.Now().Add(time.Hour); return &t }(),
	}

	mockAuth.getUserByVerificationTokenFunc = func(ctx context.Context, token string) (core.User, string, error) {
		return testUser, "hash", nil
	}

	mockAuth.verifyUserFunc = func(ctx context.Context, id uuid.UUID) error {
		return nil
	}

	err := svc.VerifyEmail(context.Background(), "valid-verification-token")
	require.NoError(t, err)
}

func TestVerifyEmailInvalidToken(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	mockAuth.getUserByVerificationTokenFunc = func(ctx context.Context, token string) (core.User, string, error) {
		return core.User{}, "", domain.ErrUserNotFound
	}

	err := svc.VerifyEmail(context.Background(), "invalid-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid or expired")
}

func TestRequestPasswordResetSuccess(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	testUser := core.User{
		ID:    uuid.New(),
		Email: stringPtr("user@example.com"),
	}

	mockAuth.getUserByEmailFunc = func(ctx context.Context, email string) (core.User, string, error) {
		return testUser, "hash", nil
	}

	mockAuth.setPasswordResetTokenFunc = func(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
		return nil
	}

	err := svc.RequestPasswordReset(context.Background(), "user@example.com")
	require.NoError(t, err)
}

func TestRequestPasswordResetUserNotFound(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	mockAuth.getUserByEmailFunc = func(ctx context.Context, email string) (core.User, string, error) {
		return core.User{}, "", domain.ErrUserNotFound
	}

	err := svc.RequestPasswordReset(context.Background(), "nonexistent@example.com")
	require.NoError(t, err)
}

func TestResetPasswordSuccess(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	testUser := core.User{
		ID:    uuid.New(),
		Email: stringPtr("user@example.com"),
	}

	mockAuth.getUserByPasswordResetTokenFunc = func(ctx context.Context, token string) (core.User, string, error) {
		return testUser, "oldhash", nil
	}

	mockAuth.updateUserPasswordFunc = func(ctx context.Context, id uuid.UUID, passwordHash string) error {
		return nil
	}

	err := svc.ResetPassword(context.Background(), "valid-reset-token", "NewPassword123!")
	require.NoError(t, err)
}

func TestResetPasswordInvalidToken(t *testing.T) {
	svc, mockAuth, _, _ := newAuthServiceWithMocks(t, 5, 5*time.Minute)

	mockAuth.getUserByPasswordResetTokenFunc = func(ctx context.Context, token string) (core.User, string, error) {
		return core.User{}, "", domain.ErrUserNotFound
	}

	err := svc.ResetPassword(context.Background(), "invalid-token", "NewPassword123!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid or expired")
}
