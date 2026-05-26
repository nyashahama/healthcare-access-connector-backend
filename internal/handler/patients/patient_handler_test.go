package patients

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
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockPatientService struct {
	mock.Mock
}

func (m *MockPatientService) CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
	args := m.Called(ctx, profile)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *MockPatientService) GetPatientProfile(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *MockPatientService) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *MockPatientService) GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error) {
	args := m.Called(ctx, nationalID)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *MockPatientService) UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error {
	args := m.Called(ctx, profile)
	return args.Error(0)
}

func (m *MockPatientService) DeletePatientProfile(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockPatientService) DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockPatientService) SearchPatients(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]patients.PatientProfile), args.Error(1)
}

func (m *MockPatientService) GetDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return patients.PatientDemographicsSummary{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientDemographicsSummary), args.Error(1)
}

func (m *MockPatientService) GetPatientByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func setupTestPatientHandler(mockService *MockPatientService) *PatientHandler {
	logger := zerolog.New(nil)
	return NewPatientHandler(mockService, &logger, 0)
}

func addUserToContext(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func createTestPatientProfile(id, userID uuid.UUID) patients.PatientProfile {
	return patients.PatientProfile{
		ID:                           id,
		UserID:                       userID,
		FirstName:                    "John",
		LastName:                     "Doe",
		Country:                      "Kenya",
		PreferredCommunicationMethod: "email",
		Timezone:                     "Africa/Nairobi",
		CreatedAt:                    time.Now(),
		UpdatedAt:                    time.Now(),
	}
}

func TestPatientHandler_CreatePatientProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		userID := uuid.New()
		profile := createTestPatientProfile(uuid.New(), userID)

		mockService.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockService.On("CreatePatientProfile", mock.Anything, mock.Anything).Return(profile, nil).Once()

		claims := &service.TokenClaims{UserID: userID, Email: "test@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"user_id": "` + userID.String() + `",
			"first_name": "John",
			"last_name": "Doe",
			"country": "Kenya",
			"preferred_communication_method": "email",
			"timezone": "Africa/Nairobi"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/patients", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreatePatientProfile(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		userID := uuid.New()
		claims := &service.TokenClaims{UserID: userID, Email: "test@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"user_id": "` + userID.String() + `",
			"first_name": "",
			"last_name": "Doe"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/patients", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreatePatientProfile(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("auth failure", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		ctx := context.Background()

		body := `{
			"user_id": "` + uuid.New().String() + `",
			"first_name": "John",
			"last_name": "Doe",
			"country": "Kenya"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/patients", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreatePatientProfile(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("forbidden", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		userID := uuid.New()
		otherUserID := uuid.New()

		claims := &service.TokenClaims{UserID: otherUserID, Email: "test@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"user_id": "` + userID.String() + `",
			"first_name": "John",
			"last_name": "Doe",
			"country": "Kenya"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/patients", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreatePatientProfile(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestPatientHandler_GetPatientProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()
		profile := createTestPatientProfile(patientID, uuid.New())

		mockService.On("GetPatientProfileByID", mock.Anything, patientID).Return(profile, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/patients/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetPatientProfile(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()
		err := domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)

		mockService.On("GetPatientProfileByID", mock.Anything, patientID).Return(patients.PatientProfile{}, err).Once()

		req := httptest.NewRequest(http.MethodGet, "/patients/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetPatientProfile(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestPatientHandler_UpdatePatientProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()
		existingProfile := createTestPatientProfile(patientID, uuid.New())
		updatedProfile := existingProfile
		updatedProfile.FirstName = "Jane"

		mockService.On("GetPatientProfileByID", mock.Anything, patientID).Return(existingProfile, nil).Once()
		mockService.On("UpdatePatientProfile", mock.Anything, mock.Anything).Return(nil).Once()
		mockService.On("GetPatientProfileByID", mock.Anything, patientID).Return(updatedProfile, nil).Once()

		body := `{
			"first_name": "Jane",
			"last_name": "Doe",
			"country": "Kenya",
			"preferred_communication_method": "email",
			"timezone": "Africa/Nairobi"
		}`

		req := httptest.NewRequest(http.MethodPut, "/patients/"+patientID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdatePatientProfile(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()
		err := domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)

		mockService.On("GetPatientProfileByID", mock.Anything, patientID).Return(patients.PatientProfile{}, err).Once()

		body := `{
			"first_name": "Jane",
			"last_name": "Doe",
			"country": "Kenya",
			"preferred_communication_method": "email",
			"timezone": "Africa/Nairobi"
		}`

		req := httptest.NewRequest(http.MethodPut, "/patients/"+patientID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdatePatientProfile(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()

		body := `{
			"first_name": "",
			"last_name": "Doe",
			"country": "Kenya"
		}`

		req := httptest.NewRequest(http.MethodPut, "/patients/"+patientID.String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdatePatientProfile(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPatientHandler_SearchPatients(t *testing.T) {
	t.Run("success with results", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		profiles := []patients.PatientProfile{
			createTestPatientProfile(uuid.New(), uuid.New()),
			createTestPatientProfile(uuid.New(), uuid.New()),
		}

		mockService.On("SearchPatients", mock.Anything, mock.Anything).Return(profiles, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/patients/search?q=john", nil)

		w := httptest.NewRecorder()
		handler.SearchPatients(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		assert.Equal(t, 2, int(response["count"].(float64)))
		assert.NotNil(t, response["patients"])

		mockService.AssertExpectations(t)
	})

	t.Run("empty query", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		profiles := []patients.PatientProfile{}

		mockService.On("SearchPatients", mock.Anything, mock.Anything).Return(profiles, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/patients/search", nil)

		w := httptest.NewRecorder()
		handler.SearchPatients(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		assert.Equal(t, 0, int(response["count"].(float64)))
		assert.NotNil(t, response["patients"])

		mockService.AssertExpectations(t)
	})

	t.Run("no results", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		profiles := []patients.PatientProfile{}

		mockService.On("SearchPatients", mock.Anything, mock.Anything).Return(profiles, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/patients/search?q=nonexistent", nil)

		w := httptest.NewRecorder()
		handler.SearchPatients(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		assert.Equal(t, 0, int(response["count"].(float64)))

		mockService.AssertExpectations(t)
	})
}

func TestPatientHandler_DeletePatientProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()

		mockService.On("DeletePatientProfile", mock.Anything, patientID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodDelete, "/patients/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeletePatientProfile(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockPatientService)
		handler := setupTestPatientHandler(mockService)

		patientID := uuid.New()
		err := domain.NewAppError(domain.ErrPatientNotFound, "Patient not found", 404)

		mockService.On("DeletePatientProfile", mock.Anything, patientID).Return(err).Once()

		req := httptest.NewRequest(http.MethodDelete, "/patients/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeletePatientProfile(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}
