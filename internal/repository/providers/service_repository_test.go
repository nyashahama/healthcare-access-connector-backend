package providers

import (
	"context"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func intPtr(i int) *int {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
}

func boolPtr(b bool) *bool {
	return &b
}

func TestServiceRepository_CreateClinicService(t *testing.T) {
	ctx := context.Background()
	serviceID := uuid.New()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		service       providers.ClinicService
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful service creation",
			service: providers.ClinicService{
				ID:                    serviceID,
				ClinicID:              clinicID,
				ServiceName:           "General Checkup",
				ServiceCategory:       stringPtr("preventive"),
				Description:           stringPtr("Annual health checkup"),
				DurationMinutes:       intPtr(30),
				Cost:                  float64Ptr(500.00),
				CostCurrency:          "ZAR",
				IsCoveredByMedicalAid: false,
				IsActive:               true,
				RequiresAppointment:   true,
				WalkInAllowed:         false,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateClinicService", ctx, mock.Anything).Return(sqlc.ClinicService{
					ID:                    uuidToPgtype(serviceID),
					ClinicID:              uuidToPgtype(clinicID),
					ServiceName:          "General Checkup",
					ServiceCategory:       pgtype.Text{String: "preventive", Valid: true},
					Description:          pgtype.Text{String: "Annual health checkup", Valid: true},
					DurationMinutes:     pgtype.Int4{Int32: 30, Valid: true},
					Cost:                 pgtype.Numeric{Int: big.NewInt(50000), Exp: -2, Valid: true},
					CostCurrency:         pgtype.Text{String: "ZAR", Valid: true},
					IsCoveredByMedicalAid: pgtype.Bool{Bool: false, Valid: true},
					IsActive:             pgtype.Bool{Bool: true, Valid: true},
					RequiresAppointment: pgtype.Bool{Bool: true, Valid: true},
					WalkInAllowed:        pgtype.Bool{Bool: false, Valid: true},
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "database error on insert",
			service: providers.ClinicService{
				ClinicID:    clinicID,
				ServiceName: "General Checkup",
				CostCurrency: "ZAR",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateClinicService", ctx, mock.Anything).
					Return(sqlc.ClinicService{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
		{
			name: "foreign key violation",
			service: providers.ClinicService{
				ClinicID:    clinicID,
				ServiceName: "General Checkup",
				CostCurrency: "ZAR",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{Code: "23503", ConstraintName: "clinic_id"}
				m.On("CreateClinicService", ctx, mock.Anything).
					Return(sqlc.ClinicService{}, pgErr)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewServiceRepositoryWithQuerier(mockQuerier)

			service, err := repo.CreateClinicService(ctx, tt.service)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "General Checkup", service.ServiceName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestServiceRepository_GetServiceByID(t *testing.T) {
	ctx := context.Background()
	serviceID := uuid.New()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		serviceID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name:      "service found",
			serviceID: serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetServiceByID", ctx, mock.Anything).Return(sqlc.ClinicService{
					ID:           uuidToPgtype(serviceID),
					ClinicID:    uuidToPgtype(clinicID),
					ServiceName: "General Checkup",
					IsActive:    pgtype.Bool{Bool: true, Valid: true},
				}, nil)
			},
			expectedError: nil,
		},
		{
			name:      "service not found",
			serviceID: serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetServiceByID", ctx, mock.Anything).
					Return(sqlc.ClinicService{}, pgx.ErrNoRows)
			},
			expectedError: domain.ErrServiceNotFound,
		},
		{
			name:      "database error",
			serviceID: serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetServiceByID", ctx, mock.Anything).
					Return(sqlc.ClinicService{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewServiceRepositoryWithQuerier(mockQuerier)

			service, err := repo.GetServiceByID(ctx, tt.serviceID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "General Checkup", service.ServiceName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestServiceRepository_UpdateClinicService(t *testing.T) {
	ctx := context.Background()
	serviceID := uuid.New()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		service      providers.ClinicService
		mockSetup    func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful update",
			service: providers.ClinicService{
				ID:                    serviceID,
				ClinicID:              clinicID,
				ServiceName:           "General Checkup",
				Cost:                 float64Ptr(600.00),
				IsCoveredByMedicalAid: true,
				RequiresAppointment:   true,
				WalkInAllowed:         false,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateClinicService", ctx, mock.Anything).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "service not found",
			service: providers.ClinicService{
				ID:                    serviceID,
				ServiceName:           "General Checkup",
				Cost:                 float64Ptr(600.00),
				IsCoveredByMedicalAid: true,
				RequiresAppointment:   true,
				WalkInAllowed:         false,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{Code: "23502", ConstraintName: "service_pkey"}
				m.On("UpdateClinicService", ctx, mock.Anything).Return(pgErr)
			},
			expectedError: assert.AnError,
		},
		{
			name: "database error",
			service: providers.ClinicService{
				ID: serviceID,
				ServiceName: "General Checkup",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateClinicService", ctx, mock.Anything).
					Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewServiceRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateClinicService(ctx, tt.service)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestServiceRepository_GetClinicServices(t *testing.T) {
	ctx := context.Background()
	serviceID := uuid.New()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		clinicID      uuid.UUID
		mockSetup    func(*mocks.MockQuerier)
		expectedLen   int
		expectedError error
	}{
		{
			name:    "services found",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicServices", ctx, mock.Anything).Return([]sqlc.GetClinicServicesRow{
					{
						ID:           uuidToPgtype(serviceID),
						ClinicID:    uuidToPgtype(clinicID),
						ServiceName: "General Checkup",
						IsActive:    pgtype.Bool{Bool: true, Valid: true},
					},
				}, nil)
			},
			expectedLen:   1,
			expectedError: nil,
		},
		{
			name:    "empty list",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicServices", ctx, mock.Anything).Return([]sqlc.GetClinicServicesRow{}, nil)
			},
			expectedLen:   0,
			expectedError: nil,
		},
		{
			name:    "database error",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicServices", ctx, mock.Anything).
					Return([]sqlc.GetClinicServicesRow{}, assert.AnError)
			},
			expectedLen:   0,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewServiceRepositoryWithQuerier(mockQuerier)

			services, err := repo.GetClinicServices(ctx, tt.clinicID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedLen, len(services))
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestServiceRepository_DeleteClinicService(t *testing.T) {
	ctx := context.Background()
	serviceID := uuid.New()

	tests := []struct {
		name          string
		serviceID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name:      "successful deletion",
			serviceID: serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteClinicService", ctx, mock.Anything).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "database error",
			serviceID: serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteClinicService", ctx, mock.Anything).
					Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewServiceRepositoryWithQuerier(mockQuerier)

			err := repo.DeleteClinicService(ctx, tt.serviceID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestServiceRepository_ServiceExists(t *testing.T) {
	ctx := context.Background()
	serviceID := uuid.New()

	tests := []struct {
		name          string
		serviceID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedExists bool
		expectedError  error
	}{
		{
			name:          "service exists",
			serviceID:     serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("ServiceExists", ctx, mock.Anything).Return(true, nil)
			},
			expectedExists: true,
			expectedError:  nil,
		},
		{
			name:          "service does not exist",
			serviceID:     serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("ServiceExists", ctx, mock.Anything).Return(false, nil)
			},
			expectedExists: false,
			expectedError:  nil,
		},
		{
			name:          "database error",
			serviceID:     serviceID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("ServiceExists", ctx, mock.Anything).
					Return(false, assert.AnError)
			},
			expectedExists: false,
			expectedError:  assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewServiceRepositoryWithQuerier(mockQuerier)

			exists, err := repo.ServiceExists(ctx, tt.serviceID)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedExists, exists)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}