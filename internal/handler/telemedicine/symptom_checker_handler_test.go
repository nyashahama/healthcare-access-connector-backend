package telemedicine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	domainpatients "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	domaintelemedicine "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockSymptomCheckerService struct {
	mock.Mock
}

func (m *mockSymptomCheckerService) SubmitSession(ctx context.Context, session domaintelemedicine.SymptomCheckerSession) (domaintelemedicine.SymptomCheckerSession, error) {
	args := m.Called(ctx, session)
	if args.Get(0) == nil {
		return domaintelemedicine.SymptomCheckerSession{}, args.Error(1)
	}
	return args.Get(0).(domaintelemedicine.SymptomCheckerSession), args.Error(1)
}

func (m *mockSymptomCheckerService) GetSessionByID(ctx context.Context, id uuid.UUID) (domaintelemedicine.SymptomCheckerSession, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return domaintelemedicine.SymptomCheckerSession{}, args.Error(1)
	}
	return args.Get(0).(domaintelemedicine.SymptomCheckerSession), args.Error(1)
}

func (m *mockSymptomCheckerService) GetPatientSessions(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]domaintelemedicine.SymptomSessionSummary, error) {
	args := m.Called(ctx, patientID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domaintelemedicine.SymptomSessionSummary), args.Error(1)
}

func (m *mockSymptomCheckerService) GetDependentSessions(ctx context.Context, patientID, dependentID uuid.UUID) ([]domaintelemedicine.DependentSessionSummary, error) {
	args := m.Called(ctx, patientID, dependentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domaintelemedicine.DependentSessionSummary), args.Error(1)
}

func (m *mockSymptomCheckerService) GetLatestEligibleSession(ctx context.Context, patientID uuid.UUID) (domaintelemedicine.EligibleSession, error) {
	args := m.Called(ctx, patientID)
	if args.Get(0) == nil {
		return domaintelemedicine.EligibleSession{}, args.Error(1)
	}
	return args.Get(0).(domaintelemedicine.EligibleSession), args.Error(1)
}

func (m *mockSymptomCheckerService) GetSessionWithPatientContext(ctx context.Context, sessionID uuid.UUID) (domaintelemedicine.SessionWithPatientContext, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return domaintelemedicine.SessionWithPatientContext{}, args.Error(1)
	}
	return args.Get(0).(domaintelemedicine.SessionWithPatientContext), args.Error(1)
}

func (m *mockSymptomCheckerService) AbandonSession(ctx context.Context, sessionID, patientID uuid.UUID) error {
	args := m.Called(ctx, sessionID, patientID)
	return args.Error(0)
}

func (m *mockSymptomCheckerService) MarkSessionConverted(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

func (m *mockSymptomCheckerService) GetSessionsByTriageLevel(ctx context.Context, triageLevel domaintelemedicine.TriageLevel, from, to time.Time, limit, offset int) ([]domaintelemedicine.AdminSessionSummary, error) {
	args := m.Called(ctx, triageLevel, from, to, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domaintelemedicine.AdminSessionSummary), args.Error(1)
}

func (m *mockSymptomCheckerService) CountSessionsByOutcome(ctx context.Context, from, to time.Time) ([]domaintelemedicine.SessionOutcomeCount, error) {
	args := m.Called(ctx, from, to)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domaintelemedicine.SessionOutcomeCount), args.Error(1)
}

func setupSymptomCheckerHandler(symptomSvc *mockSymptomCheckerService, patientSvc *mockPatientService) *SymptomCheckerHandler {
	logger := zerolog.New(nil)
	return NewSymptomCheckerHandler(symptomSvc, patientSvc, &logger, 0)
}

func addTelemedicineUserToContext(ctx context.Context, claims *service.TokenClaims) context.Context {
	return context.WithValue(ctx, middleware.UserContextKey, claims)
}

func TestSymptomCheckerHandler_GetSessionWithPatientContext(t *testing.T) {
	t.Run("allows provider role", func(t *testing.T) {
		symptomSvc := new(mockSymptomCheckerService)
		patientSvc := new(mockPatientService)
		handler := setupSymptomCheckerHandler(symptomSvc, patientSvc)

		sessionID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "staff@example.com", Role: "provider_staff"}
		ctx := addTelemedicineUserToContext(context.Background(), claims)

		symptomSvc.On("GetSessionWithPatientContext", mock.Anything, sessionID).Return(domaintelemedicine.SessionWithPatientContext{}, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/symptom-checker/sessions/"+sessionID.String()+"/patient-context", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", sessionID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSessionWithPatientContext(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		symptomSvc.AssertExpectations(t)
	})

	t.Run("rejects patient role", func(t *testing.T) {
		symptomSvc := new(mockSymptomCheckerService)
		patientSvc := new(mockPatientService)
		handler := setupSymptomCheckerHandler(symptomSvc, patientSvc)

		sessionID := uuid.New()
		claims := &service.TokenClaims{UserID: uuid.New(), Email: "patient@example.com", Role: "patient"}
		ctx := addTelemedicineUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/symptom-checker/sessions/"+sessionID.String()+"/patient-context", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", sessionID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.GetSessionWithPatientContext(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		symptomSvc.AssertNotCalled(t, "GetSessionWithPatientContext", mock.Anything, mock.Anything)
	})
}

func TestSymptomCheckerHandler_GetSessionsByTriageLevel(t *testing.T) {
	t.Run("allows system admin", func(t *testing.T) {
		symptomSvc := new(mockSymptomCheckerService)
		patientSvc := new(mockPatientService)
		handler := setupSymptomCheckerHandler(symptomSvc, patientSvc)

		claims := &service.TokenClaims{UserID: uuid.New(), Email: "admin@example.com", Role: "system_admin"}
		ctx := addTelemedicineUserToContext(context.Background(), claims)

		symptomSvc.On("GetSessionsByTriageLevel", mock.Anything, domaintelemedicine.TriageHigh, mock.Anything, mock.Anything, 20, 0).Return([]domaintelemedicine.AdminSessionSummary{}, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/symptom-checker/admin/sessions/triage?triage_level=high&from=2026-01-01&to=2026-01-31", nil)

		w := httptest.NewRecorder()
		handler.GetSessionsByTriageLevel(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		symptomSvc.AssertExpectations(t)
	})

	t.Run("rejects non-admin role", func(t *testing.T) {
		symptomSvc := new(mockSymptomCheckerService)
		patientSvc := new(mockPatientService)
		handler := setupSymptomCheckerHandler(symptomSvc, patientSvc)

		claims := &service.TokenClaims{UserID: uuid.New(), Email: "staff@example.com", Role: "provider_staff"}
		ctx := addTelemedicineUserToContext(context.Background(), claims)

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/symptom-checker/admin/sessions/triage?triage_level=high&from=2026-01-01&to=2026-01-31", nil)

		w := httptest.NewRecorder()
		handler.GetSessionsByTriageLevel(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		symptomSvc.AssertNotCalled(t, "GetSessionsByTriageLevel", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestSymptomCheckerHandler_CountSessionsByOutcome(t *testing.T) {
	t.Run("rejects unauthenticated request", func(t *testing.T) {
		symptomSvc := new(mockSymptomCheckerService)
		patientSvc := new(mockPatientService)
		handler := setupSymptomCheckerHandler(symptomSvc, patientSvc)

		req := httptest.NewRequest(http.MethodGet, "/symptom-checker/admin/sessions/outcome-counts?from=2026-01-01&to=2026-01-31", nil)

		w := httptest.NewRecorder()
		handler.CountSessionsByOutcome(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		symptomSvc.AssertNotCalled(t, "CountSessionsByOutcome", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("allows system admin", func(t *testing.T) {
		symptomSvc := new(mockSymptomCheckerService)
		patientSvc := new(mockPatientService)
		handler := setupSymptomCheckerHandler(symptomSvc, patientSvc)

		claims := &service.TokenClaims{UserID: uuid.New(), Email: "admin@example.com", Role: "system_admin"}
		ctx := addTelemedicineUserToContext(context.Background(), claims)

		symptomSvc.On("CountSessionsByOutcome", mock.Anything, mock.Anything, mock.Anything).Return([]domaintelemedicine.SessionOutcomeCount{}, nil).Once()

		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/symptom-checker/admin/sessions/outcome-counts?from=2026-01-01&to=2026-01-31", nil)

		w := httptest.NewRecorder()
		handler.CountSessionsByOutcome(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		symptomSvc.AssertExpectations(t)
	})
}

var _ service.SymptomCheckerService = (*mockSymptomCheckerService)(nil)
var _ service.PatientService = (*mockPatientService)(nil)
var _ = domainpatients.PatientProfile{}
