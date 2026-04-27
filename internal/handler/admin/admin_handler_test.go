package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSystemAdminService struct {
	mock.Mock
}

func (m *MockSystemAdminService) CreateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error) {
	args := m.Called(ctx, sysAdmin)
	if args.Get(0) == nil {
		return admin.SystemAdmin{}, args.Error(1)
	}
	return args.Get(0).(admin.SystemAdmin), args.Error(1)
}

func (m *MockSystemAdminService) GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return admin.SystemAdmin{}, args.Error(1)
	}
	return args.Get(0).(admin.SystemAdmin), args.Error(1)
}

func setupTestAdminHandler(mockService *MockSystemAdminService) *AdminHandler {
	logger := zerolog.New(nil)
	return NewAdminHandler(mockService, &logger, 0)
}

func addUserToContext(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func createTestSystemAdmin(id, userID uuid.UUID) admin.SystemAdmin {
	return admin.SystemAdmin{
		ID:               id,
		UserID:           userID,
		AdminLevel:       "super_admin",
		AssignedRegions:  []string{"Nairobi"},
		CanManageUsers:   true,
		CanManageClinics: true,
		CanManageContent: true,
		CanViewAnalytics: true,
		CanManageSystem:  true,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

func TestAdminHandler_CreateSystemAdmin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		adminID := uuid.New()
		sysAdmin := createTestSystemAdmin(adminID, userID)

		mockService.On("CreateSystemAdmin", mock.Anything, mock.Anything).Return(sysAdmin, nil).Once()

		body := `{
			"user_id": "` + userID.String() + `",
			"admin_level": "super_admin",
			"assigned_regions": ["Nairobi"],
			"can_manage_users": true,
			"can_manage_clinics": true,
			"can_manage_content": true,
			"can_view_analytics": true,
			"can_manage_system": true
		}`

		req := httptest.NewRequest(http.MethodPost, "/admin/system-admins", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		w := httptest.NewRecorder()
		handler.CreateSystemAdmin(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("forbidden - non-admin role", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		body := `{
			"user_id": "` + uuid.New().String() + `",
			"admin_level": "super_admin"
		}`

		req := httptest.NewRequest(http.MethodPost, "/admin/system-admins", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		claims := &service.TokenClaims{UserID: uuid.New(), Role: "patient", Email: "user@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		w := httptest.NewRecorder()
		handler.CreateSystemAdmin(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("duplicate", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		mockService.On("CreateSystemAdmin", mock.Anything, mock.Anything).Return(admin.SystemAdmin{}, domain.ErrDuplicate).Once()

		body := `{
			"user_id": "` + userID.String() + `",
			"admin_level": "super_admin",
			"can_manage_users": true,
			"can_manage_clinics": true,
			"can_manage_content": true,
			"can_view_analytics": true,
			"can_manage_system": true
		}`

		req := httptest.NewRequest(http.MethodPost, "/admin/system-admins", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		w := httptest.NewRecorder()
		handler.CreateSystemAdmin(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		body := `{
			"user_id": "00000000-0000-0000-0000-000000000000",
			"admin_level": "invalid_level"
		}`

		req := httptest.NewRequest(http.MethodPost, "/admin/system-admins", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		w := httptest.NewRecorder()
		handler.CreateSystemAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Contains(t, resp, "fields")
		mockService.AssertExpectations(t)
	})
}

func TestAdminHandler_GetSystemAdminByUserID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		adminID := uuid.New()
		sysAdmin := createTestSystemAdmin(adminID, userID)

		mockService.On("GetSystemAdminByUserID", mock.Anything, userID).Return(sysAdmin, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/user/"+userID.String(), nil)

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("user_id", userID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSystemAdminByUserID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		mockService.On("GetSystemAdminByUserID", mock.Anything, userID).Return(admin.SystemAdmin{}, domain.ErrNotFound).Once()

		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/user/"+userID.String(), nil)

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("user_id", userID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSystemAdminByUserID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("forbidden - non-admin role", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/user/"+userID.String(), nil)

		claims := &service.TokenClaims{UserID: uuid.New(), Role: "patient", Email: "user@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("user_id", userID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSystemAdminByUserID(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertExpectations(t)
	})
}