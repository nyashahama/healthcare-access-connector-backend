package appointments

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
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockAppointmentService struct {
	mock.Mock
}

func (m *MockAppointmentService) BookAppointment(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error) {
	args := m.Called(ctx, appointment)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentByID(ctx context.Context, id uuid.UUID, requestedBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, requestedBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentsByPatient(ctx context.Context, patientID uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, patientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentsByClinic(ctx context.Context, clinicID uuid.UUID, requestedBy uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID, requestedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentsByClinicAndDate(ctx context.Context, clinicID uuid.UUID, date time.Time, requestedBy uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID, date, requestedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetTodayAppointments(ctx context.Context, clinicID uuid.UUID, requestedBy uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID, requestedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetPendingAppointments(ctx context.Context, clinicID uuid.UUID, requestedBy uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID, requestedBy)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentCount(ctx context.Context, patientID uuid.UUID) (int64, error) {
	args := m.Called(ctx, patientID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAppointmentService) RescheduleAppointment(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time, rescheduledBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, newDate, newTime, newDatetime, rescheduledBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) ConfirmAppointment(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, confirmedBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) UpdateAppointmentNotes(ctx context.Context, id uuid.UUID, notes string, updatedBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, notes, updatedBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) CompleteAppointment(ctx context.Context, id uuid.UUID, completedBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, completedBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) CancelAppointment(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, reason, cancelledBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) UpdateAppointmentStatus(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus, updatedBy uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id, status, updatedBy)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) DeleteAppointment(ctx context.Context, id uuid.UUID, deletedBy uuid.UUID) error {
	args := m.Called(ctx, id, deletedBy)
	return args.Error(0)
}

func setupTestAppointmentHandler(mockService *MockAppointmentService) *AppointmentHandler {
	logger := zerolog.New(nil)
	return NewAppointmentHandler(mockService, &logger, 0)
}

func addUserToContext(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func createTestAppointment(id, clinicID, patientID uuid.UUID) appointments.Appointment {
	return appointments.Appointment{
		ID:                  id,
		ClinicID:            clinicID,
		PatientID:           patientID,
		AppointmentDate:     time.Now().Add(24 * time.Hour),
		AppointmentTime:     time.Now().Add(24 * time.Hour),
		AppointmentDatetime: time.Now().Add(24 * time.Hour),
		PatientName:         "John Doe",
		PatientPhone:        "+254700000000",
		ReasonForVisit:      "Checkup",
		Status:              appointments.StatusPending,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
}

func TestAppointmentHandler_CreateAppointment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		clinicID := uuid.New()
		patientID := uuid.New()
		appointment := createTestAppointment(uuid.New(), clinicID, patientID)
		claims := &service.TokenClaims{UserID: patientID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("BookAppointment", mock.Anything, mock.Anything).Return(appointment, nil).Once()

		body := `{
			"clinic_id": "` + clinicID.String() + `",
			"patient_id": "` + patientID.String() + `",
			"patient_name": "John Doe",
			"patient_phone": "+254700000000",
			"reason_for_visit": "Checkup",
			"appointment_date": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_time": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_datetime": "` + time.Now().Add(48*time.Hour).Format(time.RFC3339) + `"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("conflict", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		clinicID := uuid.New()
		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: patientID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)
		err := domain.NewAppError(domain.ErrAppointmentConflict, "appointment time conflict", 409)

		mockService.On("BookAppointment", mock.Anything, mock.Anything).Return(appointments.Appointment{}, err).Once()

		body := `{
			"clinic_id": "` + clinicID.String() + `",
			"patient_id": "` + patientID.String() + `",
			"patient_name": "John Doe",
			"patient_phone": "+254700000000",
			"reason_for_visit": "Checkup",
			"appointment_date": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_time": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_datetime": "` + time.Now().Add(48*time.Hour).Format(time.RFC3339) + `"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"clinic_id": "` + uuid.New().String() + `",
			"patient_name": ""
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		clinicID := uuid.New()
		patientID := uuid.New()
		body := `{
			"clinic_id": "` + clinicID.String() + `",
			"patient_id": "` + patientID.String() + `",
			"patient_name": "John Doe",
			"patient_phone": "+254700000000",
			"reason_for_visit": "Checkup",
			"appointment_date": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_time": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_datetime": "` + time.Now().Add(48*time.Hour).Format(time.RFC3339) + `"
		}`

		req := httptest.NewRequest(http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "BookAppointment")
	})

	t.Run("rejects patient creating appointment for another user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		clinicID := uuid.New()
		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		body := `{
			"clinic_id": "` + clinicID.String() + `",
			"patient_id": "` + patientID.String() + `",
			"patient_name": "John Doe",
			"patient_phone": "+254700000000",
			"reason_for_visit": "Checkup",
			"appointment_date": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_time": "` + time.Now().Add(24*time.Hour).Format(time.RFC3339) + `",
			"appointment_datetime": "` + time.Now().Add(48*time.Hour).Format(time.RFC3339) + `"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertNotCalled(t, "BookAppointment")
	})
}

func TestAppointmentHandler_GetAppointmentByID(t *testing.T) {
	t.Run("success for owning patient", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		patientID := uuid.New()
		appointment := createTestAppointment(appointmentID, uuid.New(), patientID)
		claims := &service.TokenClaims{UserID: patientID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("GetAppointmentByID", mock.Anything, appointmentID, patientID).Return(appointment, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentByID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()

		req := httptest.NewRequest(http.MethodGet, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentByID(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "GetAppointmentByID", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects patient reading another user's appointment", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		forbiddenErr := domain.NewAppError(domain.ErrForbidden, "Cannot view another user's appointment", 403)
		mockService.On("GetAppointmentByID", mock.Anything, appointmentID, claims.UserID).Return(appointments.Appointment{}, forbiddenErr).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentByID(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		err := domain.NewAppError(domain.ErrAppointmentNotFound, "appointment not found", 404)
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "staff@example.com", Role: "provider_staff"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("GetAppointmentByID", mock.Anything, appointmentID, claims.UserID).Return(appointments.Appointment{}, err).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentByID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAppointmentHandler_GetAppointmentsByClinic(t *testing.T) {
	t.Run("allows provider role", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		clinicID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "staff@example.com", Role: "provider_staff"}
		ctx := addUserToContext(context.Background(), claims)
		appointmentList := []appointments.Appointment{
			createTestAppointment(uuid.New(), clinicID, uuid.New()),
		}

		mockService.On("GetAppointmentsByClinic", mock.Anything, clinicID, claims.UserID).Return(appointmentList, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/clinic/"+clinicID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("clinicId", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentsByClinic(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("rejects patient role", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		clinicID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/clinic/"+clinicID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("clinicId", clinicID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentsByClinic(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertNotCalled(t, "GetAppointmentsByClinic", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_RescheduleAppointment(t *testing.T) {
	t.Run("uses authenticated actor", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		userID := uuid.New()
		newDate := time.Now().Add(48 * time.Hour)
		newTime := newDate
		newDatetime := newDate
		rescheduled := createTestAppointment(appointmentID, uuid.New(), userID)
		rescheduled.AppointmentDate = newDate
		rescheduled.AppointmentTime = newTime
		rescheduled.AppointmentDatetime = newDatetime
		claims := &service.TokenClaims{UserID: userID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("RescheduleAppointment", mock.Anything, appointmentID, mock.Anything, mock.Anything, mock.Anything, userID).Return(rescheduled, nil).Once()

		body := `{
			"appointment_date": "` + newDate.Format(time.RFC3339) + `",
			"appointment_time": "` + newTime.Format(time.RFC3339) + `",
			"appointment_datetime": "` + newDatetime.Format(time.RFC3339) + `"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/reschedule", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.RescheduleAppointment(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		newDate := time.Now().Add(48 * time.Hour)
		body := `{
			"appointment_date": "` + newDate.Format(time.RFC3339) + `",
			"appointment_time": "` + newDate.Format(time.RFC3339) + `",
			"appointment_datetime": "` + newDate.Format(time.RFC3339) + `"
		}`

		req := httptest.NewRequest(http.MethodPut, "/appointments/"+appointmentID.String()+"/reschedule", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.RescheduleAppointment(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "RescheduleAppointment", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_GetAppointmentsByPatient(t *testing.T) {
	t.Run("success with results", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: patientID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)
		appointmentList := []appointments.Appointment{
			createTestAppointment(uuid.New(), uuid.New(), patientID),
			createTestAppointment(uuid.New(), uuid.New(), patientID),
		}

		mockService.On("GetAppointmentsByPatient", mock.Anything, patientID).Return(appointmentList, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/patient/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentsByPatient(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 2, int(response["count"].(float64)))

		mockService.AssertExpectations(t)
	})

	t.Run("empty list", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: patientID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)
		appointmentList := []appointments.Appointment{}

		mockService.On("GetAppointmentsByPatient", mock.Anything, patientID).Return(appointmentList, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/patient/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentsByPatient(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, int(response["count"].(float64)))

		mockService.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()

		req := httptest.NewRequest(http.MethodGet, "/appointments/patient/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentsByPatient(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "GetAppointmentsByPatient", mock.Anything, mock.Anything)
	})

	t.Run("rejects patient requesting another patient history", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/patient/"+patientID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentsByPatient(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertNotCalled(t, "GetAppointmentsByPatient", mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_CancelAppointment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		cancelledBy := uuid.New()
		spoofedCancelledBy := uuid.New()
		cancelledAppointment := createTestAppointment(appointmentID, uuid.New(), uuid.New())
		cancelledAppointment.Status = appointments.StatusCancelled
		claims := &service.TokenClaims{UserID: cancelledBy, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("CancelAppointment", mock.Anything, appointmentID, "Personal reasons", cancelledBy).Return(cancelledAppointment, nil).Once()

		body := `{
			"cancellation_reason": "Personal reasons",
			"cancelled_by": "` + spoofedCancelledBy.String() + `"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/cancel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.CancelAppointment(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		cancelledBy := uuid.New()
		err := domain.NewAppError(domain.ErrAppointmentNotFound, "appointment not found", 404)
		claims := &service.TokenClaims{UserID: cancelledBy, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("CancelAppointment", mock.Anything, appointmentID, "Personal reasons", cancelledBy).Return(appointments.Appointment{}, err).Once()

		body := `{
			"cancellation_reason": "Personal reasons",
			"cancelled_by": "` + cancelledBy.String() + `"
		}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/cancel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.CancelAppointment(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		body := `{
			"cancellation_reason": "Personal reasons",
			"cancelled_by": "` + uuid.New().String() + `"
		}`

		req := httptest.NewRequest(http.MethodPut, "/appointments/"+appointmentID.String()+"/cancel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.CancelAppointment(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "CancelAppointment", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_ConfirmAppointment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		userID := uuid.New()
		confirmedAppointment := createTestAppointment(appointmentID, uuid.New(), uuid.New())
		confirmedAppointment.Status = appointments.StatusConfirmed

		claims := &service.TokenClaims{UserID: userID, Email: "staff@example.com", Role: "staff"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("ConfirmAppointment", mock.Anything, appointmentID, userID).Return(confirmedAppointment, nil).Once()

		body := `{"confirmed_by": "` + userID.String() + `"}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/confirm", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.ConfirmAppointment(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("forbidden patient tries to confirm", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		userID := uuid.New()
		err := domain.NewAppError(domain.ErrForbidden, "only staff can confirm", 403)

		claims := &service.TokenClaims{UserID: userID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("ConfirmAppointment", mock.Anything, appointmentID, userID).Return(appointments.Appointment{}, err).Once()

		body := `{"confirmed_by": "` + userID.String() + `"}`

		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/confirm", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.ConfirmAppointment(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAppointmentHandler_CompleteAppointment(t *testing.T) {
	t.Run("uses authenticated actor", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		userID := uuid.New()
		completedAppointment := createTestAppointment(appointmentID, uuid.New(), uuid.New())
		completedAppointment.Status = appointments.StatusCompleted

		claims := &service.TokenClaims{UserID: userID, Email: "staff@example.com", Role: "staff"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("CompleteAppointment", mock.Anything, appointmentID, userID).Return(completedAppointment, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/complete", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.CompleteAppointment(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()

		req := httptest.NewRequest(http.MethodPut, "/appointments/"+appointmentID.String()+"/complete", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.CompleteAppointment(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "CompleteAppointment", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_UpdateAppointmentStatus(t *testing.T) {
	t.Run("uses authenticated actor", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		userID := uuid.New()
		updatedAppointment := createTestAppointment(appointmentID, uuid.New(), uuid.New())
		updatedAppointment.Status = appointments.StatusConfirmed

		claims := &service.TokenClaims{UserID: userID, Email: "staff@example.com", Role: "staff"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("UpdateAppointmentStatus", mock.Anything, appointmentID, appointments.StatusConfirmed, userID).Return(updatedAppointment, nil).Once()

		body := `{"status":"confirmed"}`
		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/appointments/"+appointmentID.String()+"/status", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateAppointmentStatus(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		body := `{"status":"confirmed"}`

		req := httptest.NewRequest(http.MethodPut, "/appointments/"+appointmentID.String()+"/status", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdateAppointmentStatus(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "UpdateAppointmentStatus", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_DeleteAppointment(t *testing.T) {
	t.Run("uses authenticated actor", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		userID := uuid.New()
		claims := &service.TokenClaims{UserID: userID, Email: "staff@example.com", Role: "staff"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("DeleteAppointment", mock.Anything, appointmentID, userID).Return(nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodDelete, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteAppointment(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("requires authenticated user", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()

		req := httptest.NewRequest(http.MethodDelete, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.DeleteAppointment(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "DeleteAppointment", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestAppointmentHandler_GetAppointmentCount(t *testing.T) {
	t.Run("uses authenticated patient for own count", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: patientID, Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		mockService.On("GetAppointmentCount", mock.Anything, patientID).Return(int64(3), nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/patient/"+patientID.String()+"/count", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentCount(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()

		req := httptest.NewRequest(http.MethodGet, "/appointments/patient/"+patientID.String()+"/count", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentCount(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertNotCalled(t, "GetAppointmentCount", mock.Anything, mock.Anything)
	})

	t.Run("rejects patient requesting another patient count", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/appointments/patient/"+patientID.String()+"/count", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("patientId", patientID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentCount(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockService.AssertNotCalled(t, "GetAppointmentCount", mock.Anything, mock.Anything)
	})
}
