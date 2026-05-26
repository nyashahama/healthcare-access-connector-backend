package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockClinicService struct {
	mock.Mock
}

func (m *MockClinicService) RegisterClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
	args := m.Called(ctx, clinic, createdBy, ownerUserID)
	if args.Get(0) == nil {
		return providers.Clinic{}, args.Error(1)
	}
	return args.Get(0).(providers.Clinic), args.Error(1)
}

func (m *MockClinicService) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return providers.Clinic{}, args.Error(1)
	}
	return args.Get(0).(providers.Clinic), args.Error(1)
}

func (m *MockClinicService) GetClinicByUserID(ctx context.Context, userID uuid.UUID) (*providers.Clinic, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*providers.Clinic), args.Error(1)
}

func (m *MockClinicService) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	args := m.Called(ctx, clinic)
	return args.Error(0)
}

func (m *MockClinicService) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockClinicService) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	args := m.Called(ctx, id, verifiedBy, notes)
	return args.Error(0)
}

func (m *MockClinicService) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	args := m.Called(ctx, id, verifiedBy, notes)
	return args.Error(0)
}

func (m *MockClinicService) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockClinicService) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockClinicService) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockClinicService) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.ClinicSearchResult), args.Error(1)
}

func (m *MockClinicService) GetClinics(ctx context.Context) ([]providers.Clinic, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.Clinic), args.Error(1)
}

func (m *MockClinicService) GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error) {
	args := m.Called(ctx, ownerUserID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*providers.Clinic), args.Error(1)
}

func (m *MockClinicService) GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicWithOwner, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*providers.ClinicWithOwner), args.Error(1)
}

func (m *MockClinicService) UpdateClinicOwner(ctx context.Context, clinicID, newOwnerUserID, updatedBy uuid.UUID) error {
	args := m.Called(ctx, clinicID, newOwnerUserID, updatedBy)
	return args.Error(0)
}

func (m *MockClinicService) GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicVerification, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*providers.ClinicVerification), args.Error(1)
}

func setupTestClinicHandler(mockService *MockClinicService) *ClinicHandler {
	logger := zerolog.New(nil)
	return NewClinicHandler(mockService, &logger, 0)
}

func addUserToContext(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func TestClinicHandler_CreateClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		userID := uuid.New()
		clinic := providers.Clinic{
			ID:              uuid.New(),
			ClinicName:      "Test Clinic",
			ClinicType:      "public_health_clinic",
			PhysicalAddress: "123 Test St",
			Country:         "Kenya",
		}

		mockService.On("RegisterClinic", mock.Anything, mock.Anything, userID, userID).Return(clinic, nil).Once()

		claims := &service.TokenClaims{UserID: userID, Email: "test@example.com", Role: "provider"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"clinic_name": "Test Clinic",
			"clinic_type": "public_health_clinic",
			"physical_address": "123 Test St",
			"country": "Kenya"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/clinics", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateClinic(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		userID := uuid.New()
		claims := &service.TokenClaims{UserID: userID, Email: "test@example.com", Role: "provider"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"clinic_type": "public_health_clinic",
			"physical_address": "123 Test St",
			"country": "Kenya"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/clinics", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateClinic(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("auth failure", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		ctx := context.Background()

		body := `{
			"clinic_name": "Test Clinic",
			"clinic_type": "public_health_clinic",
			"physical_address": "123 Test St",
			"country": "Kenya"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/clinics", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateClinic(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestClinicHandler_GetClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()
		clinic := providers.Clinic{
			ID:              clinicID,
			ClinicName:      "Test Clinic",
			ClinicType:      "public_health_clinic",
			PhysicalAddress: "123 Test St",
			Country:         "Kenya",
		}

		mockService.On("GetClinicByID", mock.Anything, clinicID).Return(clinic, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/clinics/"+clinicID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetClinic(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()
		err := domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)

		mockService.On("GetClinicByID", mock.Anything, clinicID).Return(providers.Clinic{}, err).Once()

		req := httptest.NewRequest(http.MethodGet, "/clinics/"+clinicID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetClinic(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestClinicHandler_GetMyClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		userID := uuid.New()
		clinic := providers.Clinic{
			ID:              uuid.New(),
			ClinicName:      "My Clinic",
			ClinicType:      "private_clinic",
			PhysicalAddress: "456 Main St",
			Country:         "Kenya",
			OwnerUserID:     &userID,
		}

		mockService.On("GetClinicByUserID", mock.Anything, userID).Return(&clinic, nil).Once()

		claims := &service.TokenClaims{UserID: userID, Email: "test@example.com", Role: "provider"}
		ctx := addUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/my-clinic", nil)

		w := httptest.NewRecorder()
		handler.GetMyClinic(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotNil(t, response["clinic"])

		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		userID := uuid.New()
		err := domain.NewAppError(domain.ErrClinicNotFound, "No clinic found for this user", 404)

		mockService.On("GetClinicByUserID", mock.Anything, userID).Return(nil, err).Once()

		claims := &service.TokenClaims{UserID: userID, Email: "test@example.com", Role: "provider"}
		ctx := addUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/my-clinic", nil)

		w := httptest.NewRecorder()
		handler.GetMyClinic(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestClinicHandler_UpdateClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()
		existingClinic := providers.Clinic{
			ID:              clinicID,
			ClinicName:      "Old Name",
			ClinicType:      "public_health_clinic",
			PhysicalAddress: "123 Test St",
			Country:         "Kenya",
		}
		updatedClinic := providers.Clinic{
			ID:              clinicID,
			ClinicName:      "New Name",
			ClinicType:      "public_health_clinic",
			PhysicalAddress: "123 Test St",
			Country:         "Kenya",
		}

		mockService.On("GetClinicByID", mock.Anything, clinicID).Return(existingClinic, nil).Once()
		mockService.On("UpdateClinic", mock.Anything, mock.Anything).Return(nil).Once()
		mockService.On("GetClinicByID", mock.Anything, clinicID).Return(updatedClinic, nil).Once()

		body := `{
			"clinic_name": "New Name",
			"clinic_type": "public_health_clinic",
			"physical_address": "123 Test St",
			"country": "Kenya"
		}`

		req := httptest.NewRequest(http.MethodPut, "/clinics/"+clinicID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateClinic(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()
		err := domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)

		mockService.On("GetClinicByID", mock.Anything, clinicID).Return(providers.Clinic{}, err).Once()

		body := `{
			"clinic_name": "New Name",
			"clinic_type": "public_health_clinic",
			"physical_address": "123 Test St",
			"country": "Kenya"
		}`

		req := httptest.NewRequest(http.MethodPut, "/clinics/"+clinicID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateClinic(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()

		body := `{
			"clinic_type": "public_health_clinic",
			"physical_address": "123 Test St",
			"country": "Kenya"
		}`

		req := httptest.NewRequest(http.MethodPut, "/clinics/"+clinicID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateClinic(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestClinicHandler_ListClinics(t *testing.T) {
	t.Run("success with list", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinics := []providers.Clinic{
			{ID: uuid.New(), ClinicName: "Clinic 1", ClinicType: "public_health_clinic", PhysicalAddress: "123 St", Country: "Kenya"},
			{ID: uuid.New(), ClinicName: "Clinic 2", ClinicType: "private_clinic", PhysicalAddress: "456 Ave", Country: "Kenya"},
		}

		mockService.On("GetClinics", mock.Anything).Return(clinics, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/clinics", nil)

		w := httptest.NewRecorder()
		handler.ListClinics(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 2, int(response["count"].(float64)))
		assert.NotNil(t, response["clinics"])

		mockService.AssertExpectations(t)
	})

	t.Run("empty list", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		mockService.On("GetClinics", mock.Anything).Return([]providers.Clinic{}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/clinics", nil)

		w := httptest.NewRecorder()
		handler.ListClinics(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, 0, int(response["count"].(float64)))
		assert.NotNil(t, response["clinics"])

		mockService.AssertExpectations(t)
	})
}

func TestClinicHandler_DeleteClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()

		mockService.On("DeleteClinic", mock.Anything, clinicID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodDelete, "/clinics/"+clinicID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteClinic(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockClinicService)
		handler := setupTestClinicHandler(mockService)

		clinicID := uuid.New()
		err := domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)

		mockService.On("DeleteClinic", mock.Anything, clinicID).Return(err).Once()

		req := httptest.NewRequest(http.MethodDelete, "/clinics/"+clinicID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteClinic(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}
