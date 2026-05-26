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

type MockNGOPartnerService struct {
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

func (m *MockSystemAdminService) GetSystemAdmin(ctx context.Context, id uuid.UUID) (admin.SystemAdmin, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return admin.SystemAdmin{}, args.Error(1)
	}
	return args.Get(0).(admin.SystemAdmin), args.Error(1)
}

func (m *MockSystemAdminService) UpdateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error) {
	args := m.Called(ctx, sysAdmin)
	if args.Get(0) == nil {
		return admin.SystemAdmin{}, args.Error(1)
	}
	return args.Get(0).(admin.SystemAdmin), args.Error(1)
}

func (m *MockSystemAdminService) DeleteSystemAdmin(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockSystemAdminService) DeleteSystemAdminByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockSystemAdminService) SearchSystemAdmins(ctx context.Context, params admin.SystemAdminSearchParams) ([]admin.SystemAdmin, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]admin.SystemAdmin), args.Error(1)
}

func (m *MockNGOPartnerService) CreateNGOPartner(ctx context.Context, partner admin.NGOPartner) (admin.NGOPartner, error) {
	args := m.Called(ctx, partner)
	if args.Get(0) == nil {
		return admin.NGOPartner{}, args.Error(1)
	}
	return args.Get(0).(admin.NGOPartner), args.Error(1)
}

func (m *MockNGOPartnerService) GetNGOPartnerByUserID(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return admin.NGOPartner{}, args.Error(1)
	}
	return args.Get(0).(admin.NGOPartner), args.Error(1)
}

func setupTestAdminHandler(mockService *MockSystemAdminService, mockNGOService ...*MockNGOPartnerService) *AdminHandler {
	logger := zerolog.New(nil)
	var ngoSvc *MockNGOPartnerService
	if len(mockNGOService) > 0 {
		ngoSvc = mockNGOService[0]
	}
	return NewAdminHandler(mockService, ngoSvc, &logger, 0)
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
		handler := setupTestAdminHandler(mockService, new(MockNGOPartnerService))

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
		handler := setupTestAdminHandler(mockService, new(MockNGOPartnerService))

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
		handler := setupTestAdminHandler(mockService, new(MockNGOPartnerService))

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
		handler := setupTestAdminHandler(mockService, new(MockNGOPartnerService))

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
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Contains(t, resp, "fields")
		mockService.AssertExpectations(t)
	})
}

func TestAdminHandler_GetSystemAdminByUserID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService, new(MockNGOPartnerService))

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

func TestAdminHandler_GetSystemAdmin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		userID := uuid.New()
		sysAdmin := createTestSystemAdmin(adminID, userID)

		mockService.On("GetSystemAdmin", mock.Anything, adminID).Return(sysAdmin, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/"+adminID.String(), nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", adminID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSystemAdmin(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		mockService.On("GetSystemAdmin", mock.Anything, adminID).Return(admin.SystemAdmin{}, domain.ErrNotFound).Once()

		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/"+adminID.String(), nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", adminID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSystemAdmin(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAdminHandler_UpdateSystemAdmin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		existing := createTestSystemAdmin(adminID, uuid.New())
		updated := existing
		updated.AdminLevel = "regional"

		body := `{"admin_level":"regional","can_manage_users":true}`

		mockService.On("GetSystemAdmin", mock.Anything, adminID).Return(existing, nil).Once()
		mockService.On("UpdateSystemAdmin", mock.Anything, mock.MatchedBy(func(req admin.SystemAdmin) bool {
			return req.ID == adminID && req.AdminLevel == "regional"
		})).Return(updated, nil).Once()

		req := httptest.NewRequest(http.MethodPut, "/admin/system-admins/"+adminID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", adminID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateSystemAdmin(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("invalid admin level", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		body := `{"admin_level":"invalid"}`

		req := httptest.NewRequest(http.MethodPut, "/admin/system-admins/"+adminID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", adminID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateSystemAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("no fields", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		body := `{}`

		req := httptest.NewRequest(http.MethodPut, "/admin/system-admins/"+adminID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", adminID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateSystemAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAdminHandler_DeleteSystemAdmin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		mockService.On("DeleteSystemAdmin", mock.Anything, adminID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodDelete, "/admin/system-admins/"+adminID.String(), nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", adminID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteSystemAdmin(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("invalid id", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		req := httptest.NewRequest(http.MethodDelete, "/admin/system-admins/not-a-uuid", nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "not-a-uuid")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteSystemAdmin(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAdminHandler_DeleteSystemAdminByUserID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		mockService.On("DeleteSystemAdminByUserID", mock.Anything, userID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodDelete, "/admin/system-admins/user/"+userID.String(), nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("user_id", userID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteSystemAdminByUserID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		userID := uuid.New()
		mockService.On("DeleteSystemAdminByUserID", mock.Anything, userID).Return(domain.ErrNotFound).Once()

		req := httptest.NewRequest(http.MethodDelete, "/admin/system-admins/user/"+userID.String(), nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("user_id", userID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteSystemAdminByUserID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAdminHandler_SearchSystemAdmins(t *testing.T) {
	t.Run("success with filters", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		adminID := uuid.New()
		userID := uuid.New()
		sysAdmin := createTestSystemAdmin(adminID, userID)
		result := []admin.SystemAdmin{sysAdmin}

		expected := admin.SystemAdminSearchParams{
			AdminLevel: "super_admin",
			Region:     "North",
			Department: "Cardiology",
			Query:      "john",
			Limit:      10,
			Offset:     2,
		}

		mockService.On("SearchSystemAdmins", mock.Anything, expected).Return(result, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/search?admin_level=super_admin&region=North&department=Cardiology&query=john&limit=10&offset=2", nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		w := httptest.NewRecorder()
		handler.SearchSystemAdmins(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("invalid admin level", func(t *testing.T) {
		mockService := new(MockSystemAdminService)
		handler := setupTestAdminHandler(mockService)

		req := httptest.NewRequest(http.MethodGet, "/admin/system-admins/search?admin_level=invalid", nil)
		adminIDClaims := uuid.New()
		claims := &service.TokenClaims{UserID: adminIDClaims, Role: "system_admin", Email: "admin@example.com"}
		req = req.WithContext(addUserToContext(req.Context(), claims))

		w := httptest.NewRecorder()
		handler.SearchSystemAdmins(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})
}
