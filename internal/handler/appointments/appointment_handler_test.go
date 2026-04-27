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

func (m *MockAppointmentService) GetAppointmentByID(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id)
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

func (m *MockAppointmentService) GetAppointmentsByClinic(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentsByClinicAndDate(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID, date)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetTodayAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetPendingAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) GetAppointmentCount(ctx context.Context, patientID uuid.UUID) (int64, error) {
	args := m.Called(ctx, patientID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAppointmentService) RescheduleAppointment(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error) {
	args := m.Called(ctx, id, newDate, newTime, newDatetime)
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

func (m *MockAppointmentService) UpdateAppointmentNotes(ctx context.Context, id uuid.UUID, notes string) (appointments.Appointment, error) {
	args := m.Called(ctx, id, notes)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) CompleteAppointment(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	args := m.Called(ctx, id)
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

func (m *MockAppointmentService) UpdateAppointmentStatus(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus) (appointments.Appointment, error) {
	args := m.Called(ctx, id, status)
	if args.Get(0) == nil {
		return appointments.Appointment{}, args.Error(1)
	}
	return args.Get(0).(appointments.Appointment), args.Error(1)
}

func (m *MockAppointmentService) DeleteAppointment(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
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
		ID:                   id,
		ClinicID:             clinicID,
		PatientID:            patientID,
		AppointmentDate:     time.Now().Add(24 * time.Hour),
		AppointmentTime:     time.Now().Add(24 * time.Hour),
		AppointmentDatetime: time.Now().Add(24 * time.Hour),
		PatientName:         "John Doe",
		PatientPhone:        "+254700000000",
		ReasonForVisit:       "Checkup",
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

		req := httptest.NewRequest(http.MethodPost, "/appointments", bytes.NewBufferString(body))
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

		req := httptest.NewRequest(http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		body := `{
			"clinic_id": "` + uuid.New().String() + `",
			"patient_name": ""
		}`

		req := httptest.NewRequest(http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("auth failure", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		body := `{"missing": "fields"}`

		req := httptest.NewRequest(http.MethodPost, "/appointments", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.CreateAppointment(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAppointmentHandler_GetAppointmentByID(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		appointment := createTestAppointment(appointmentID, uuid.New(), uuid.New())

		mockService.On("GetAppointmentByID", mock.Anything, appointmentID).Return(appointment, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentByID(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		err := domain.NewAppError(domain.ErrAppointmentNotFound, "appointment not found", 404)

		mockService.On("GetAppointmentByID", mock.Anything, appointmentID).Return(appointments.Appointment{}, err).Once()

		req := httptest.NewRequest(http.MethodGet, "/appointments/"+appointmentID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetAppointmentByID(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestAppointmentHandler_GetAppointmentsByPatient(t *testing.T) {
	t.Run("success with results", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		patientID := uuid.New()
		appointmentList := []appointments.Appointment{
			createTestAppointment(uuid.New(), uuid.New(), patientID),
			createTestAppointment(uuid.New(), uuid.New(), patientID),
		}

		mockService.On("GetAppointmentsByPatient", mock.Anything, patientID).Return(appointmentList, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/appointments/patient/"+patientID.String(), nil)
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
		appointmentList := []appointments.Appointment{}

		mockService.On("GetAppointmentsByPatient", mock.Anything, patientID).Return(appointmentList, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/appointments/patient/"+patientID.String(), nil)
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
}

func TestAppointmentHandler_CancelAppointment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockService := new(MockAppointmentService)
		handler := setupTestAppointmentHandler(mockService)

		appointmentID := uuid.New()
		cancelledBy := uuid.New()
		cancelledAppointment := createTestAppointment(appointmentID, uuid.New(), uuid.New())
		cancelledAppointment.Status = appointments.StatusCancelled

		mockService.On("CancelAppointment", mock.Anything, appointmentID, "Personal reasons", cancelledBy).Return(cancelledAppointment, nil).Once()

		body := `{
			"cancellation_reason": "Personal reasons",
			"cancelled_by": "` + cancelledBy.String() + `"
		}`

		req := httptest.NewRequest(http.MethodPut, "/appointments/"+appointmentID.String()+"/cancel", bytes.NewBufferString(body))
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

		mockService.On("CancelAppointment", mock.Anything, appointmentID, "Personal reasons", cancelledBy).Return(appointments.Appointment{}, err).Once()

		body := `{
			"cancellation_reason": "Personal reasons",
			"cancelled_by": "` + cancelledBy.String() + `"
		}`

		req := httptest.NewRequest(http.MethodPut, "/appointments/"+appointmentID.String()+"/cancel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", appointmentID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.CancelAppointment(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
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