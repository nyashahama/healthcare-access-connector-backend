package core

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, email, phone, password, role string) (core.User, error) {
	args := m.Called(ctx, email, phone, password, role)
	return args.Get(0).(core.User), args.Error(1)
}

func (m *MockAuthService) RegisterInvitedStaff(ctx context.Context, token, email, password, phone string) (core.User, error) {
	args := m.Called(ctx, token, email, password, phone)
	return args.Get(0).(core.User), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, identifier, password, ipAddress, userAgent string) (string, time.Time, core.User, error) {
	args := m.Called(ctx, identifier, password, ipAddress, userAgent)
	return args.String(0), args.Get(1).(time.Time), args.Get(2).(core.User), args.Error(3)
}

func (m *MockAuthService) Logout(ctx context.Context, tokenString string, userID uuid.UUID) error {
	args := m.Called(ctx, tokenString, userID)
	return args.Error(0)
}

func (m *MockAuthService) ValidateToken(ctx context.Context, token string) (*service.TokenClaims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.TokenClaims), args.Error(1)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, tokenString string, ipAddress, userAgent string) (string, time.Time, core.User, error) {
	args := m.Called(ctx, tokenString, ipAddress, userAgent)
	return args.String(0), args.Get(1).(time.Time), args.Get(2).(core.User), args.Error(3)
}

func (m *MockAuthService) VerifyEmail(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) RequestPasswordReset(ctx context.Context, identifier string) error {
	args := m.Called(ctx, identifier)
	return args.Error(0)
}

func (m *MockAuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	args := m.Called(ctx, token, newPassword)
	return args.Error(0)
}

func (m *MockAuthService) ResendVerificationEmail(ctx context.Context, email string) error {
	args := m.Called(ctx, email)
	return args.Error(0)
}

func (m *MockAuthService) UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error {
	args := m.Called(ctx, userID, step)
	return args.Error(0)
}

func (m *MockAuthService) UpdateUserPrimaryClinic(ctx context.Context, userID, clinicID uuid.UUID) error {
	args := m.Called(ctx, userID, clinicID)
	return args.Error(0)
}

func (m *MockAuthService) CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockAuthService) GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*core.ProviderWithClinic), args.Error(1)
}

func (m *MockAuthService) GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]core.UserClinic), args.Error(1)
}

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) GetProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(core.User), args.Get(1).(patients.PatientProfile), args.Error(2)
}

func (m *MockUserService) GetUserByID(ctx context.Context, userID uuid.UUID) (core.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(core.User), args.Error(1)
}

func (m *MockUserService) UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error {
	args := m.Called(ctx, userID, updates)
	return args.Error(0)
}

func (m *MockUserService) UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	args := m.Called(ctx, userID, currentPassword, newPassword)
	return args.Error(0)
}

func (m *MockUserService) DeleteProfile(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	args := m.Called(ctx, role, limit, offset)
	return args.Get(0).([]core.User), args.Error(1)
}

func (m *MockUserService) GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(core.PrivacyConsent), args.Error(1)
}

func (m *MockUserService) UpdateConsent(ctx context.Context, userID uuid.UUID, consent core.PrivacyConsent) error {
	args := m.Called(ctx, userID, consent)
	return args.Error(0)
}

func (m *MockUserService) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	args := m.Called(ctx, id, email)
	return args.Error(0)
}

func (m *MockUserService) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	args := m.Called(ctx, id, phone)
	return args.Error(0)
}

func (m *MockUserService) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	args := m.Called(ctx, id, role)
	return args.Error(0)
}

func (m *MockUserService) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockUserService) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	args := m.Called(ctx, id, percentage)
	return args.Error(0)
}

func (m *MockUserService) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	args := m.Called(ctx, id, smsConsent, popiaConsent, consentDate)
	return args.Error(0)
}

func (m *MockUserService) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	args := m.Called(ctx, ids, status)
	return args.Error(0)
}

func (m *MockUserService) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	args := m.Called(ctx, ids)
	return args.Get(0).([]core.User), args.Error(1)
}

func (m *MockUserService) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	args := m.Called(ctx, query, role, status)
	return args.Get(0).([]core.User), args.Error(1)
}

func (m *MockUserService) CountUsers(ctx context.Context, role string) (int64, error) {
	args := m.Called(ctx, role)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserService) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(core.User), args.Get(1).(patients.PatientProfile), args.Error(2)
}

func newTestHandler(authSvc *MockAuthService, userSvc *MockUserService) *AuthHandler {
	logger := zerolog.New(nil)
	return NewAuthHandler(authSvc, userSvc, &logger, 5*time.Second)
}

func newTestRequest(method, path string, body []byte) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAuthHandler_Register(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		userID := uuid.New()
		email := "test@example.com"
		user := core.User{
			ID:        userID,
			Email:     &email,
			Role:      "patient",
			Status:    "active",
			IsVerified: false,
			CreatedAt: time.Now(),
		}

		mockAuth.On("Register", mock.Anything, email, "", "password123", "patient").Return(user, nil)

		body := []byte(`{"email":"test@example.com","password":"password123","role":"patient"}`)
		req := newTestRequest("POST", "/api/v1/auth/register", body)
		w := httptest.NewRecorder()

		handler.Register(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("validation error - missing password", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		body := []byte(`{"email":"test@example.com"}`)
		req := newTestRequest("POST", "/api/v1/auth/register", body)
		w := httptest.NewRecorder()

		handler.Register(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service error - duplicate email", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		email := "test@example.com"
		mockAuth.On("Register", mock.Anything, email, "", "password123", "patient").Return(core.User{}, domain.ErrDuplicateEmail)

		body := []byte(`{"email":"test@example.com","password":"password123","role":"patient"}`)
		req := newTestRequest("POST", "/api/v1/auth/register", body)
		w := httptest.NewRecorder()

		handler.Register(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		mockAuth.AssertExpectations(t)
	})
}

func TestAuthHandler_Login(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		userID := uuid.New()
		email := "test@example.com"
		user := core.User{
			ID:        userID,
			Email:     &email,
			Role:      "patient",
			Status:    "active",
			IsVerified: true,
			CreatedAt: time.Now(),
		}

		mockAuth.On("Login", mock.Anything, "test@example.com", "password123", mock.Anything, mock.Anything).Return("token", time.Now().Add(time.Hour), user, nil)

		body := []byte(`{"identifier":"test@example.com","password":"password123"}`)
		req := newTestRequest("POST", "/api/v1/auth/login", body)
		w := httptest.NewRecorder()

		handler.Login(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("Login", mock.Anything, "test@example.com", "wrongpassword", mock.Anything, mock.Anything).Return("", time.Time{}, core.User{}, domain.ErrInvalidCredentials)

		body := []byte(`{"identifier":"test@example.com","password":"wrongpassword"}`)
		req := newTestRequest("POST", "/api/v1/auth/login", body)
		w := httptest.NewRecorder()

		handler.Login(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		body := []byte(`{"identifier":"test@example.com"}`)
		req := newTestRequest("POST", "/api/v1/auth/login", body)
		w := httptest.NewRecorder()

		handler.Login(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		userID := uuid.New()
		email := "test@example.com"
		user := core.User{
			ID:        userID,
			Email:     &email,
			Role:      "patient",
			Status:    "active",
			IsVerified: true,
			CreatedAt: time.Now(),
		}

		mockAuth.On("RefreshToken", mock.Anything, "valid-token", mock.Anything, mock.Anything).Return("new-token", time.Now().Add(time.Hour), user, nil)

		req := newTestRequest("GET", "/api/v1/auth/refresh", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		handler.RefreshToken(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("expired token", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("RefreshToken", mock.Anything, "expired-token", mock.Anything, mock.Anything).Return("", time.Time{}, core.User{}, domain.ErrExpiredToken)

		req := newTestRequest("GET", "/api/v1/auth/refresh", nil)
		req.Header.Set("Authorization", "Bearer expired-token")
		w := httptest.NewRecorder()

		handler.RefreshToken(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockAuth.AssertExpectations(t)
	})
}

func TestAuthHandler_Logout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		userID := uuid.New()
		mockAuth.On("ValidateToken", mock.Anything, "valid-token").Return(&service.TokenClaims{UserID: userID}, nil)
		mockAuth.On("Logout", mock.Anything, "valid-token", userID).Return(nil)

		req := newTestRequest("POST", "/api/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		handler.Logout(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("missing token", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		req := newTestRequest("POST", "/api/v1/auth/logout", nil)
		w := httptest.NewRecorder()

		handler.Logout(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAuthHandler_VerifyEmail(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("VerifyEmail", mock.Anything, "valid-token").Return(nil)

		req := newTestRequest("GET", "/api/v1/auth/verify-email?token=valid-token", nil)
		w := httptest.NewRecorder()

		handler.VerifyEmail(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("VerifyEmail", mock.Anything, "invalid-token").Return(domain.ErrInvalidToken)

		req := newTestRequest("GET", "/api/v1/auth/verify-email?token=invalid-token", nil)
		w := httptest.NewRecorder()

		handler.VerifyEmail(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockAuth.AssertExpectations(t)
	})
}

func TestAuthHandler_RequestPasswordReset(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("RequestPasswordReset", mock.Anything, "test@example.com").Return(nil)

		body := []byte(`{"identifier":"test@example.com"}`)
		req := newTestRequest("POST", "/api/v1/auth/request-password-reset", body)
		w := httptest.NewRecorder()

		handler.RequestPasswordReset(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		body := []byte(`{}`)
		req := newTestRequest("POST", "/api/v1/auth/request-password-reset", body)
		w := httptest.NewRecorder()

		handler.RequestPasswordReset(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_ResetPassword(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("ResetPassword", mock.Anything, "valid-token", "newpassword123").Return(nil)

		body := []byte(`{"token":"valid-token","new_password":"newpassword123"}`)
		req := newTestRequest("POST", "/api/v1/auth/reset-password", body)
		w := httptest.NewRecorder()

		handler.ResetPassword(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("invalid token", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("ResetPassword", mock.Anything, "invalid-token", "newpassword123").Return(domain.ErrInvalidToken)

		body := []byte(`{"token":"invalid-token","new_password":"newpassword123"}`)
		req := newTestRequest("POST", "/api/v1/auth/reset-password", body)
		w := httptest.NewRecorder()

		handler.ResetPassword(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("weak password", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		body := []byte(`{"token":"valid-token","new_password":"weak"}`)
		req := newTestRequest("POST", "/api/v1/auth/reset-password", body)
		w := httptest.NewRecorder()

		handler.ResetPassword(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_ResendVerificationEmail(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		mockAuth.On("ResendVerificationEmail", mock.Anything, "test@example.com").Return(nil)

		body := []byte(`{"email":"test@example.com"}`)
		req := newTestRequest("POST", "/api/v1/auth/resend-verification", body)
		w := httptest.NewRecorder()

		handler.ResendVerificationEmail(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockAuth.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockAuth := new(MockAuthService)
		mockUser := new(MockUserService)
		handler := newTestHandler(mockAuth, mockUser)

		body := []byte(`{"email":"invalid-email"}`)
		req := newTestRequest("POST", "/api/v1/auth/resend-verification", body)
		w := httptest.NewRecorder()

		handler.ResendVerificationEmail(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}