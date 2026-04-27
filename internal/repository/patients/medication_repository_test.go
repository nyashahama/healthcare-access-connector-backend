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

func TestMedicationRepository_AddPatientMedication(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	medicationID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	status := "Active"

	tests := []struct {
		name       string
		medication patients.PatientMedication
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			medication: patients.PatientMedication{
				PatientID:      patientID,
				MedicationName: "Aspirin",
				Status:         status,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientMedication{
					ID:             uuidPgtypeFromString(medicationID.String()),
					PatientID:      uuidPgtypeFromString(patientID.String()),
					MedicationName: "Aspirin",
					Status:         pgtype.Text{String: status, Valid: true},
					CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:      pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddPatientMedication", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			medication: patients.PatientMedication{
				PatientID:      patientID,
				MedicationName: "Aspirin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientMedication", ctx, mock.Anything).Return(sqlc.PatientMedication{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			medication: patients.PatientMedication{
				PatientID:      patientID,
				MedicationName: "Aspirin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientMedication", ctx, mock.Anything).Return(sqlc.PatientMedication{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicationRepositoryWithQuerier(mockQuerier)

			gotMedication, err := repo.AddPatientMedication(ctx, tt.medication)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Aspirin", gotMedication.MedicationName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestMedicationRepository_GetPatientMedications(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	medicationID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	status := "Active"

	tests := []struct {
		name       string
		patientID  uuid.UUID
		status     *string
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name:      "success",
			patientID: patientID,
			status:    &status,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRows := []sqlc.GetPatientMedicationsRow{
					{
						ID:             uuidPgtypeFromString(medicationID.String()),
						PatientID:      uuidPgtypeFromString(patientID.String()),
						MedicationName: "Aspirin",
						Status:         pgtype.Text{String: status, Valid: true},
						CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:      pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientMedications", ctx, mock.Anything).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			status:    &status,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientMedications", ctx, mock.Anything).Return([]sqlc.GetPatientMedicationsRow{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			status:    &status,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientMedications", ctx, mock.Anything).Return([]sqlc.GetPatientMedicationsRow{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicationRepositoryWithQuerier(mockQuerier)

			gotMedications, err := repo.GetPatientMedications(ctx, tt.patientID, tt.status)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotMedications, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestMedicationRepository_UpdatePatientMedication(t *testing.T) {
	ctx := context.Background()
	medicationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		medication patients.PatientMedication
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			medication: patients.PatientMedication{
				ID:             medicationID,
				MedicationName: "Aspirin",
				Status:         "Inactive",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientMedication", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			medication: patients.PatientMedication{
				ID:             medicationID,
				MedicationName: "Aspirin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientMedication", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			medication: patients.PatientMedication{
				ID:             medicationID,
				MedicationName: "Aspirin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientMedication", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicationRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientMedication(ctx, tt.medication)

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

func TestMedicationRepository_DeletePatientMedication(t *testing.T) {
	ctx := context.Background()
	medicationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   medicationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientMedication", ctx, uuidPgtypeFromString(medicationID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   medicationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientMedication", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   medicationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientMedication", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicationRepositoryWithQuerier(mockQuerier)

			err := repo.DeletePatientMedication(ctx, tt.id)

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