package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type mockAuthService struct {
	validToken   string
	returnClaims *service.TokenClaims
	err          error
}

func (m *mockAuthService) Register(ctx context.Context, email, phone, password, role string) (core.User, error) {
	return core.User{}, nil
}
func (m *mockAuthService) RegisterInvitedStaff(ctx context.Context, token, email, password, phone string) (core.User, error) {
	return core.User{}, nil
}
func (m *mockAuthService) Login(ctx context.Context, identifier, password, ipAddress, userAgent string) (string, time.Time, core.User, error) {
	return "", time.Time{}, core.User{}, nil
}
func (m *mockAuthService) Logout(ctx context.Context, tokenString string, userID uuid.UUID) error {
	return nil
}
func (m *mockAuthService) ValidateToken(ctx context.Context, token string) (*service.TokenClaims, error) {
	if token == m.validToken {
		return m.returnClaims, nil
	}
	return nil, m.err
}
func (m *mockAuthService) RefreshToken(ctx context.Context, tokenString string, ipAddress, userAgent string) (string, time.Time, core.User, error) {
	return "", time.Time{}, core.User{}, nil
}
func (m *mockAuthService) VerifyEmail(ctx context.Context, token string) error {
	return nil
}
func (m *mockAuthService) RequestPasswordReset(ctx context.Context, identifier string) error {
	return nil
}
func (m *mockAuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	return nil
}
func (m *mockAuthService) ResendVerificationEmail(ctx context.Context, email string) error {
	return nil
}
func (m *mockAuthService) UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error {
	return nil
}
func (m *mockAuthService) UpdateUserPrimaryClinic(ctx context.Context, userID, clinicID uuid.UUID) error {
	return nil
}
func (m *mockAuthService) CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *mockAuthService) GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error) {
	return nil, nil
}
func (m *mockAuthService) GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error) {
	return nil, nil
}

func TestAuthMiddlewareMissingHeader(t *testing.T) {
	logger := zerolog.New(nil)
	mock := &mockAuthService{}
	handler := AuthMiddleware(mock, &logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing authorization token")
}

func TestAuthMiddlewareInvalidFormat(t *testing.T) {
	logger := zerolog.New(nil)
	mock := &mockAuthService{}
	handler := AuthMiddleware(mock, &logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic abc123")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid authorization header format")
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	logger := zerolog.New(nil)
	mock := &mockAuthService{
		validToken: "valid-jwt-token",
		returnClaims: &service.TokenClaims{
			UserID: uuid.MustParse("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
			Role:   "patient",
			Email:  "test@example.com",
		},
	}
	handler := AuthMiddleware(mock, &logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetUserFromContext(r.Context())
		if !ok {
			t.Error("expected claims in context")
		}
		assert.Equal(t, "patient", claims.Role)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-jwt-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireRoleAllowsMatchingRole(t *testing.T) {
	handler := RequireRole("admin", "system_admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), UserContextKey, &service.TokenClaims{Role: "admin"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireRoleBlocksNonMatchingRole(t *testing.T) {
	handler := RequireRole("admin", "system_admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), UserContextKey, &service.TokenClaims{Role: "patient"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "Insufficient permissions")
}

func TestRequireRoleBlocksMissingClaims(t *testing.T) {
	handler := RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}
