package telemedicine

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
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockConsultationService struct {
	mock.Mock
}

func (m *mockConsultationService) RequestConsultation(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error) {
	args := m.Called(ctx, c)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) GetConsultationByID(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) GetConsultationWithDetails(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationWithDetails, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return telemedicine.ConsultationWithDetails{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.ConsultationWithDetails), args.Error(1)
}

func (m *mockConsultationService) GetPatientConsultations(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.PatientConsultationSummary, error) {
	args := m.Called(ctx, patientID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]telemedicine.PatientConsultationSummary), args.Error(1)
}

func (m *mockConsultationService) GetPatientActiveConsultation(ctx context.Context, patientID uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
	args := m.Called(ctx, patientID)
	if args.Get(0) == nil {
		return telemedicine.ActiveConsultationCheck{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.ActiveConsultationCheck), args.Error(1)
}

func (m *mockConsultationService) CancelConsultation(ctx context.Context, id uuid.UUID, cancelledBy uuid.UUID) (telemedicine.Consultation, error) {
	args := m.Called(ctx, id, cancelledBy)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) SubmitPatientRating(ctx context.Context, id uuid.UUID, patientID uuid.UUID, rating int, feedback *string) error {
	args := m.Called(ctx, id, patientID, rating, feedback)
	return args.Error(0)
}

func (m *mockConsultationService) AcceptConsultation(ctx context.Context, id uuid.UUID, providerStaffID uuid.UUID, clinicID uuid.UUID) (telemedicine.Consultation, error) {
	args := m.Called(ctx, id, providerStaffID, clinicID)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) StartConsultation(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) CompleteConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	args := m.Called(ctx, id, endedBy)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) EscalateConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	args := m.Called(ctx, id, endedBy)
	if args.Get(0) == nil {
		return telemedicine.Consultation{}, args.Error(1)
	}
	return args.Get(0).(telemedicine.Consultation), args.Error(1)
}

func (m *mockConsultationService) DeclineConsultation(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockConsultationService) MarkNoShow(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockConsultationService) GetProviderActiveConsultations(ctx context.Context, providerStaffID uuid.UUID) ([]telemedicine.ProviderActiveConsultation, error) {
	args := m.Called(ctx, providerStaffID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]telemedicine.ProviderActiveConsultation), args.Error(1)
}

func (m *mockConsultationService) GetWaitingRoom(ctx context.Context) ([]telemedicine.WaitingRoomEntry, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]telemedicine.WaitingRoomEntry), args.Error(1)
}

func (m *mockConsultationService) GetProviderConsultationHistory(ctx context.Context, providerStaffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderConsultationHistoryEntry, error) {
	args := m.Called(ctx, providerStaffID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]telemedicine.ProviderConsultationHistoryEntry), args.Error(1)
}

func (m *mockConsultationService) UpdatePaymentStatus(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error {
	args := m.Called(ctx, id, status, reference)
	return args.Error(0)
}

func (m *mockConsultationService) UpdateConsultationChannel(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error {
	args := m.Called(ctx, id, channel)
	return args.Error(0)
}

func (m *mockConsultationService) LinkFollowUpAppointment(ctx context.Context, id uuid.UUID, appointmentID uuid.UUID) error {
	args := m.Called(ctx, id, appointmentID)
	return args.Error(0)
}

type mockPatientService struct {
	mock.Mock
}

func (m *mockPatientService) CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
	args := m.Called(ctx, profile)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *mockPatientService) GetPatientProfile(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *mockPatientService) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *mockPatientService) GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error) {
	args := m.Called(ctx, nationalID)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

func (m *mockPatientService) UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error {
	args := m.Called(ctx, profile)
	return args.Error(0)
}

func (m *mockPatientService) DeletePatientProfile(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockPatientService) DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *mockPatientService) SearchPatients(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]patients.PatientProfile), args.Error(1)
}

func (m *mockPatientService) GetDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return patients.PatientDemographicsSummary{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientDemographicsSummary), args.Error(1)
}

func (m *mockPatientService) GetPatientByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return patients.PatientProfile{}, args.Error(1)
	}
	return args.Get(0).(patients.PatientProfile), args.Error(1)
}

type mockStaffService struct {
	mock.Mock
}

func (m *mockStaffService) CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error) {
	args := m.Called(ctx, staff)
	if args.Get(0) == nil {
		return providers.ClinicStaff{}, args.Error(1)
	}
	return args.Get(0).(providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return providers.ClinicStaff{}, args.Error(1)
	}
	return args.Get(0).(providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return providers.ClinicStaff{}, args.Error(1)
	}
	return args.Get(0).(providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error {
	args := m.Called(ctx, staff)
	return args.Error(0)
}

func (m *mockStaffService) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockStaffService) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error) {
	args := m.Called(ctx, clinicID, role)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	args := m.Called(ctx, id)
	return args.Bool(0), args.Error(1)
}

func (m *mockStaffService) CreateStaffInvitation(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error) {
	args := m.Called(ctx, invitation)
	if args.Get(0) == nil {
		return providers.ClinicStaff{}, args.Error(1)
	}
	return args.Get(0).(providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) GetStaffInvitationByToken(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*providers.StaffInvitationDetails), args.Error(1)
}

func (m *mockStaffService) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) (providers.ClinicStaff, error) {
	args := m.Called(ctx, token, userID)
	if args.Get(0) == nil {
		return providers.ClinicStaff{}, args.Error(1)
	}
	return args.Get(0).(providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) DeclineStaffInvitation(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *mockStaffService) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	args := m.Called(ctx, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]providers.StaffInvitationDetails, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]providers.StaffInvitationDetails), args.Error(1)
}

func (m *mockStaffService) CancelStaffInvitation(ctx context.Context, token string, cancelledBy uuid.UUID) error {
	args := m.Called(ctx, token, cancelledBy)
	return args.Error(0)
}

func (m *mockStaffService) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID, resentBy uuid.UUID) (string, error) {
	args := m.Called(ctx, invitationID, resentBy)
	return args.String(0), args.Error(1)
}

func (m *mockStaffService) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
	args := m.Called(ctx, userID, clinicID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*providers.ClinicStaff), args.Error(1)
}

func (m *mockStaffService) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions providers.StaffPermissions, updatedBy uuid.UUID) error {
	args := m.Called(ctx, staffID, permissions, updatedBy)
	return args.Error(0)
}

func (m *mockStaffService) ExpireStaffInvitations(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func setupTestHandler() *ConsultationHandler {
	logger := zerolog.New(nil)
	mockConsultationSvc := new(mockConsultationService)
	mockPatientSvc := new(mockPatientService)
	mockStaffSvc := new(mockStaffService)
	return NewConsultationHandler(mockConsultationSvc, mockPatientSvc, mockStaffSvc, &logger, 5*time.Second)
}

func newTestConsultation(id uuid.UUID) telemedicine.Consultation {
	now := time.Now()
	return telemedicine.Consultation{
		ID:                id,
		SymptomSessionID:  uuid.New(),
		PatientID:        uuid.New(),
		Channel:          telemedicine.ChannelChat,
		Status:           telemedicine.ConsultationStatusPendingAcceptance,
		FeeCurrency:      "ZAR",
		PaymentStatus:    telemedicine.PaymentStatusPending,
		RequestedAt:      &now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func newActiveConsultationCheck(id uuid.UUID) telemedicine.ActiveConsultationCheck {
	return telemedicine.ActiveConsultationCheck{
		ID:      id,
		Status:  telemedicine.ConsultationStatusInProgress,
		Channel: telemedicine.ChannelChat,
	}
}

func addUserToCtx(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func TestConsultationHandler_RequestConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)

		patientID := uuid.New()
		userID := uuid.New()
		consultation := newTestConsultation(uuid.New())
		consultation.PatientID = patientID

		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{
			ID: patientID,
		}, nil).Once()

		mockConsultationSvc.On("RequestConsultation", mock.Anything, mock.Anything).Return(consultation, nil).Once()

		body := map[string]interface{}{
			"symptom_session_id": uuid.New().String(),
			"channel":            "chat",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/consultations", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.RequestConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusCreated, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("no provider available (503)", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)

		userID := uuid.New()

		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{
			ID: uuid.New(),
		}, nil).Once()

		err := domain.NewAppError(domain.ErrServiceNotAvailable, "no providers available", 503)
		mockConsultationSvc.On("RequestConsultation", mock.Anything, mock.Anything).Return(telemedicine.Consultation{}, err).Once()

		body := map[string]interface{}{
			"symptom_session_id": uuid.New().String(),
			"channel":            "chat",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/consultations", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.RequestConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("already active (409)", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)

		userID := uuid.New()

		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{
			ID: uuid.New(),
		}, nil).Once()

		err := domain.NewAppError(domain.ErrConflict, "patient already has an active consultation", 409)
		mockConsultationSvc.On("RequestConsultation", mock.Anything, mock.Anything).Return(telemedicine.Consultation{}, err).Once()

		body := map[string]interface{}{
			"symptom_session_id": uuid.New().String(),
			"channel":            "chat",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/consultations", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.RequestConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusConflict, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("auth failure (401)", func(t *testing.T) {
		handler := setupTestHandler()

		body := map[string]interface{}{
			"symptom_session_id": uuid.New().String(),
			"channel":            "chat",
		}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/consultations", bytes.NewBuffer(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		handler.RequestConsultation(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestConsultationHandler_AcceptConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()
		clinicID := uuid.New()

		consultation := newTestConsultation(consultationID)
		consultation.Status = telemedicine.ConsultationStatusAccepted

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{
			ID:      staffID,
			ClinicID: clinicID,
		}, nil).Once()

		mockConsultationSvc.On("AcceptConsultation", mock.Anything, consultationID, staffID, clinicID).Return(consultation, nil).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/accept", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.AcceptConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("already accepted (409)", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()
		clinicID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{
			ID:      staffID,
			ClinicID: clinicID,
		}, nil).Once()

		err := domain.NewAppError(domain.ErrConflict, "consultation is not pending acceptance", 409)
		mockConsultationSvc.On("AcceptConsultation", mock.Anything, consultationID, staffID, clinicID).Return(telemedicine.Consultation{}, err).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/accept", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.AcceptConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusConflict, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("staff not found returns unauthorized (401)", func(t *testing.T) {
		handler := setupTestHandler()
		mockStaffSvc := handler.staffService.(*mockStaffService)

		userID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{}, domain.NewAppError(domain.ErrStaffNotFound, "staff not found", 403)).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+uuid.New().String()+"/accept", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", uuid.New().String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.AcceptConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestConsultationHandler_StartConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.Status = telemedicine.ConsultationStatusInProgress

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{
			ID: uuid.New(),
		}, nil).Once()
		mockConsultationSvc.On("StartConsultation", mock.Anything, consultationID).Return(consultation, nil).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/start", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.StartConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("wrong state (409)", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{
			ID: uuid.New(),
		}, nil).Once()
		err := domain.NewAppError(domain.ErrValidation, "consultation must be in accepted state", 409)
		mockConsultationSvc.On("StartConsultation", mock.Anything, consultationID).Return(telemedicine.Consultation{}, err).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/start", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.StartConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusConflict, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("requires authenticated staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/start", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.StartConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "StartConsultation", mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_DeclineConsultation(t *testing.T) {
	t.Run("allows authenticated staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New()}, nil).Once()
		mockConsultationSvc.On("DeclineConsultation", mock.Anything, consultationID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/decline", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.DeclineConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/decline", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.DeclineConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "DeclineConsultation", mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_MarkNoShow(t *testing.T) {
	t.Run("allows authenticated staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New()}, nil).Once()
		mockConsultationSvc.On("MarkNoShow", mock.Anything, consultationID).Return(nil).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/no-show", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.MarkNoShow(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/no-show", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.MarkNoShow(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "MarkNoShow", mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_CompleteConsultation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()

		consultation := newTestConsultation(consultationID)
		consultation.Status = telemedicine.ConsultationStatusCompleted

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{
			ID: staffID,
		}, nil).Once()

		mockConsultationSvc.On("CompleteConsultation", mock.Anything, consultationID, staffID).Return(consultation, nil).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/complete", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.CompleteConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("notes not finalized (409)", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{
			ID: staffID,
		}, nil).Once()

		err := domain.NewAppError(domain.ErrValidation, "consultation notes must be finalized before completing", 409)
		mockConsultationSvc.On("CompleteConsultation", mock.Anything, consultationID, staffID).Return(telemedicine.Consultation{}, err).Once()

		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/complete", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.CompleteConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusConflict, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})
}

func TestConsultationHandler_GetPatientActiveConsultation(t *testing.T) {
	t.Run("success with active consultation", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)

		userID := uuid.New()
		patientID := uuid.New()

		activeCheck := newActiveConsultationCheck(uuid.New())

		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{
			ID: patientID,
		}, nil).Once()

		mockConsultationSvc.On("GetPatientActiveConsultation", mock.Anything, patientID).Return(activeCheck, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/me/active", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.GetPatientActiveConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})

	t.Run("no active consultation returns 404", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)

		userID := uuid.New()
		patientID := uuid.New()

		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{
			ID: patientID,
		}, nil).Once()

		err := domain.NewAppError(domain.ErrNotFound, "no active consultation", 404)
		mockConsultationSvc.On("GetPatientActiveConsultation", mock.Anything, patientID).Return(telemedicine.ActiveConsultationCheck{}, err).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/me/active", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.GetPatientActiveConsultation(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockConsultationSvc.AssertExpectations(t)
	})
}

func TestConsultationHandler_GetConsultationByID(t *testing.T) {
	t.Run("allows owning patient", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		consultationID := uuid.New()
		userID := uuid.New()
		patientID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.PatientID = patientID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{ID: patientID}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationByID(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
	})

	t.Run("allows assigned provider staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.ProviderStaffID = &staffID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: staffID}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationByID(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unrelated authenticated user", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		patientID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.PatientID = patientID
		otherStaffID := uuid.New()
		consultation.ProviderStaffID = &otherStaffID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New()}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationByID(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String(), nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationByID(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "GetConsultationByID", mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_GetConsultationWithDetails(t *testing.T) {
	t.Run("allows owning patient", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		consultationID := uuid.New()
		userID := uuid.New()
		patientID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.PatientID = patientID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockConsultationSvc.On("GetConsultationWithDetails", mock.Anything, consultationID).Return(telemedicine.ConsultationWithDetails{}, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{ID: patientID}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String()+"/details", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationWithDetails(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
	})

	t.Run("allows assigned provider staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.ProviderStaffID = &staffID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockConsultationSvc.On("GetConsultationWithDetails", mock.Anything, consultationID).Return(telemedicine.ConsultationWithDetails{}, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: staffID}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String()+"/details", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationWithDetails(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unrelated authenticated user", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		patientID := uuid.New()
		otherStaffID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.PatientID = patientID
		consultation.ProviderStaffID = &otherStaffID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New()}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String()+"/details", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationWithDetails(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
		mockConsultationSvc.AssertNotCalled(t, "GetConsultationWithDetails", mock.Anything, mock.Anything)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/consultations/"+consultationID.String()+"/details", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.GetConsultationWithDetails(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "GetConsultationByID", mock.Anything, mock.Anything)
		mockConsultationSvc.AssertNotCalled(t, "GetConsultationWithDetails", mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_GetWaitingRoom(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)
		userID := uuid.New()

		entries := []telemedicine.WaitingRoomEntry{
			{
				ID:                uuid.New(),
				Channel:           telemedicine.ChannelChat,
				PatientFirstName:  "John",
				PatientLastName:   "Doe",
				ChiefComplaint:    "Test complaint",
			},
		}

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New(), ClinicID: uuid.New()}, nil).Once()
		mockConsultationSvc.On("GetWaitingRoom", mock.Anything).Return(entries, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/waiting-room", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.GetWaitingRoom(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("empty", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)
		userID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New(), ClinicID: uuid.New()}, nil).Once()
		mockConsultationSvc.On("GetWaitingRoom", mock.Anything).Return([]telemedicine.WaitingRoomEntry{}, nil).Once()

		req := httptest.NewRequest(http.MethodGet, "/consultations/waiting-room", nil)
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.GetWaitingRoom(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("requires authenticated staff identity", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		req := httptest.NewRequest(http.MethodGet, "/consultations/waiting-room", nil)

		w := httptest.NewRecorder()
		handler.GetWaitingRoom(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "GetWaitingRoom", mock.Anything)
	})
}

func TestConsultationHandler_UpdatePaymentStatus(t *testing.T) {
	t.Run("allows authenticated staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)
		userID := uuid.New()
		consultationID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New(), ClinicID: uuid.New()}, nil).Once()
		mockConsultationSvc.On("UpdatePaymentStatus", mock.Anything, consultationID, telemedicine.PaymentStatusPaid, (*string)(nil)).Return(nil).Once()

		body := `{"status":"paid"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/payment", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.UpdatePaymentStatus(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		body := `{"status":"paid"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/payment", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.UpdatePaymentStatus(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "UpdatePaymentStatus", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_LinkFollowUpAppointment(t *testing.T) {
	t.Run("allows authenticated staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockStaffSvc := handler.staffService.(*mockStaffService)
		userID := uuid.New()
		consultationID := uuid.New()
		appointmentID := uuid.New()

		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New(), ClinicID: uuid.New()}, nil).Once()
		mockConsultationSvc.On("LinkFollowUpAppointment", mock.Anything, consultationID, appointmentID).Return(nil).Once()

		body := `{"appointment_id":"` + appointmentID.String() + `"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/follow-up", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})

		w := httptest.NewRecorder()
		handler.LinkFollowUpAppointment(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		appointmentID := uuid.New()
		body := `{"appointment_id":"` + appointmentID.String() + `"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/follow-up", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.LinkFollowUpAppointment(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "LinkFollowUpAppointment", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestConsultationHandler_UpdateConsultationChannel(t *testing.T) {
	t.Run("allows owning patient", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)

		consultationID := uuid.New()
		userID := uuid.New()
		patientID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.PatientID = patientID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{ID: patientID}, nil).Once()
		mockConsultationSvc.On("UpdateConsultationChannel", mock.Anything, consultationID, telemedicine.ChannelVideo).Return(nil).Once()

		body := `{"channel":"video"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/channel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.UpdateConsultationChannel(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
	})

	t.Run("allows assigned provider staff", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		staffID := uuid.New()
		consultation := newTestConsultation(consultationID)
		consultation.ProviderStaffID = &staffID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: staffID}, nil).Once()
		mockConsultationSvc.On("UpdateConsultationChannel", mock.Anything, consultationID, telemedicine.ChannelPhone).Return(nil).Once()

		body := `{"channel":"phone"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/channel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.UpdateConsultationChannel(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusOK, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
	})

	t.Run("rejects unrelated authenticated user", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)
		mockPatientSvc := handler.patientService.(*mockPatientService)
		mockStaffSvc := handler.staffService.(*mockStaffService)

		consultationID := uuid.New()
		userID := uuid.New()
		consultation := newTestConsultation(consultationID)
		otherStaffID := uuid.New()
		consultation.ProviderStaffID = &otherStaffID

		mockConsultationSvc.On("GetConsultationByID", mock.Anything, consultationID).Return(consultation, nil).Once()
		mockPatientSvc.On("GetPatientProfile", mock.Anything, userID).Return(patients.PatientProfile{}, domain.NewAppError(domain.ErrNotFound, "not found", 404)).Once()
		mockStaffSvc.On("GetStaffByUserID", mock.Anything, userID).Return(providers.ClinicStaff{ID: uuid.New()}, nil).Once()

		body := `{"channel":"video"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/channel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := addUserToCtx(req.Context(), &service.TokenClaims{UserID: userID})
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.UpdateConsultationChannel(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusForbidden, w.Code)
		mockConsultationSvc.AssertExpectations(t)
		mockPatientSvc.AssertExpectations(t)
		mockStaffSvc.AssertExpectations(t)
		mockConsultationSvc.AssertNotCalled(t, "UpdateConsultationChannel", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("rejects unauthenticated request", func(t *testing.T) {
		handler := setupTestHandler()
		mockConsultationSvc := handler.consultationService.(*mockConsultationService)

		consultationID := uuid.New()
		body := `{"channel":"video"}`
		req := httptest.NewRequest(http.MethodPut, "/consultations/"+consultationID.String()+"/channel", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", consultationID.String())
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)

		w := httptest.NewRecorder()
		handler.UpdateConsultationChannel(w, req.WithContext(ctx))

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockConsultationSvc.AssertNotCalled(t, "GetConsultationByID", mock.Anything, mock.Anything)
	})
}
