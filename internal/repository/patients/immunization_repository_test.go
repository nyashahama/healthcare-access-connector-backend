package patients

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestImmunizationRepository_AddPatientImmunization(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	immunizationID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	doseNumber := 1
	totalDoses := 2

	tests := []struct {
		name          string
		immunization  patients.PatientImmunization
		mockSetup     func(*mocks.MockQuerier)
		expectError   bool
		errIsNotFound bool
	}{
		{
			name: "success",
			immunization: patients.PatientImmunization{
				PatientID:          patientID,
				VaccineName:        "COVID-19",
				AdministrationDate: now,
				DoseNumber:         &doseNumber,
				TotalDoses:         &totalDoses,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientImmunization{
					ID:                 uuidPgtypeFromString(immunizationID.String()),
					PatientID:          uuidPgtypeFromString(patientID.String()),
					VaccineName:        "COVID-19",
					AdministrationDate: pgtype.Date{Time: now, Valid: true},
					DoseNumber:         pgtype.Int4{Int32: 1, Valid: true},
					TotalDoses:         pgtype.Int4{Int32: 2, Valid: true},
					CreatedAt:          pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddPatientImmunization", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectError: false,
		},
		{
			name: "not found",
			immunization: patients.PatientImmunization{
				PatientID:   patientID,
				VaccineName: "COVID-19",
				DoseNumber:  &doseNumber,
				TotalDoses:  &totalDoses,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientImmunization", ctx, mock.Anything).Return(sqlc.PatientImmunization{}, pgx.ErrNoRows)
			},
			expectError:   true,
			errIsNotFound: true,
		},
		{
			name: "database error",
			immunization: patients.PatientImmunization{
				PatientID:   patientID,
				VaccineName: "COVID-19",
				DoseNumber:  &doseNumber,
				TotalDoses:  &totalDoses,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientImmunization", ctx, mock.Anything).Return(sqlc.PatientImmunization{}, assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewImmunizationRepositoryWithQuerier(mockQuerier)

			gotImmunization, err := repo.AddPatientImmunization(ctx, tt.immunization)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "COVID-19", gotImmunization.VaccineName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestImmunizationRepository_GetPatientImmunizations(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	immunizationID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		patientID  uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name:      "success",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRows := []sqlc.GetPatientImmunizationsRow{
					{
						ID:                 uuidPgtypeFromString(immunizationID.String()),
						PatientID:          uuidPgtypeFromString(patientID.String()),
						VaccineName:        "COVID-19",
						AdministrationDate: pgtype.Date{Time: now, Valid: true},
						DoseNumber:         pgtype.Int4{Int32: 1, Valid: true},
						TotalDoses:         pgtype.Int4{Int32: 2, Valid: true},
						CreatedAt:          pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientImmunizations", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientImmunizations", ctx, uuidPgtypeFromString(patientID.String())).Return([]sqlc.GetPatientImmunizationsRow{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientImmunizations", ctx, mock.Anything).Return([]sqlc.GetPatientImmunizationsRow{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewImmunizationRepositoryWithQuerier(mockQuerier)

			gotImmunizations, err := repo.GetPatientImmunizations(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotImmunizations, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestImmunizationRepository_UpdatePatientImmunization(t *testing.T) {
	ctx := context.Background()
	immunizationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		immunization  patients.PatientImmunization
		mockSetup     func(*mocks.MockQuerier)
		expectError   bool
		errIsNotFound bool
	}{
		{
			name: "success",
			immunization: patients.PatientImmunization{
				ID:          immunizationID,
				VaccineName: "COVID-19",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientImmunization", ctx, mock.Anything).Return(nil)
			},
			expectError: false,
		},
		{
			name: "not found",
			immunization: patients.PatientImmunization{
				ID:          immunizationID,
				VaccineName: "COVID-19",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientImmunization", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectError:   true,
			errIsNotFound: true,
		},
		{
			name: "database error",
			immunization: patients.PatientImmunization{
				ID:          immunizationID,
				VaccineName: "COVID-19",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientImmunization", ctx, mock.Anything).Return(assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewImmunizationRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientImmunization(ctx, tt.immunization)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestImmunizationRepository_DeletePatientImmunization(t *testing.T) {
	ctx := context.Background()
	immunizationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   immunizationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientImmunization", ctx, uuidPgtypeFromString(immunizationID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   immunizationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientImmunization", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   immunizationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientImmunization", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewImmunizationRepositoryWithQuerier(mockQuerier)

			err := repo.DeletePatientImmunization(ctx, tt.id)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}