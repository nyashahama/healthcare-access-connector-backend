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

func TestFamilyHistoryRepository_AddFamilyHistory(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	historyID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	isAlive := true

	tests := []struct {
		name       string
		history    patients.PatientFamilyHistory
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			history: patients.PatientFamilyHistory{
				PatientID:      patientID,
				Relative:        "Father",
				ConditionName:  "Heart Disease",
				IsAlive:        &isAlive,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientFamilyHistory{
					ID:             uuidPgtypeFromString(historyID.String()),
					PatientID:      uuidPgtypeFromString(patientID.String()),
					Relative:       "Father",
					ConditionName:  "Heart Disease",
					IsAlive:        pgtype.Bool{Bool: true, Valid: true},
					CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddFamilyHistory", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			history: patients.PatientFamilyHistory{
				PatientID:     patientID,
				Relative:      "Father",
				ConditionName: "Heart Disease",
				IsAlive:        func() *bool { v := true; return &v }(),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddFamilyHistory", ctx, mock.Anything).Return(sqlc.PatientFamilyHistory{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			history: patients.PatientFamilyHistory{
				PatientID:     patientID,
				Relative:      "Father",
				ConditionName: "Heart Disease",
				IsAlive:        func() *bool { v := true; return &v }(),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddFamilyHistory", ctx, mock.Anything).Return(sqlc.PatientFamilyHistory{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewFamilyHistoryRepositoryWithQuerier(mockQuerier)

			gotHistory, err := repo.AddFamilyHistory(ctx, tt.history)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Heart Disease", gotHistory.ConditionName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestFamilyHistoryRepository_GetPatientFamilyHistory(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	historyID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

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
				expectedRows := []sqlc.PatientFamilyHistory{
					{
						ID:             uuidPgtypeFromString(historyID.String()),
						PatientID:      uuidPgtypeFromString(patientID.String()),
						Relative:       "Father",
						ConditionName:  "Heart Disease",
						IsAlive:        pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientFamilyHistory", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientFamilyHistory", ctx, uuidPgtypeFromString(patientID.String())).Return([]sqlc.PatientFamilyHistory{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientFamilyHistory", ctx, mock.Anything).Return([]sqlc.PatientFamilyHistory{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewFamilyHistoryRepositoryWithQuerier(mockQuerier)

			gotHistories, err := repo.GetPatientFamilyHistory(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotHistories, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestFamilyHistoryRepository_UpdateFamilyHistory(t *testing.T) {
	ctx := context.Background()
	historyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		history    patients.PatientFamilyHistory
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			history: patients.PatientFamilyHistory{
				ID:             historyID,
				Relative:       "Father",
				ConditionName:  "Heart Disease",
				IsAlive:        func() *bool { v := true; return &v }(),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateFamilyHistory", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			history: patients.PatientFamilyHistory{
				ID:             historyID,
				Relative:       "Father",
				ConditionName:  "Heart Disease",
				IsAlive:        func() *bool { v := true; return &v }(),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateFamilyHistory", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			history: patients.PatientFamilyHistory{
				ID:             historyID,
				Relative:       "Father",
				ConditionName:  "Heart Disease",
				IsAlive:        func() *bool { v := true; return &v }(),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateFamilyHistory", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewFamilyHistoryRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateFamilyHistory(ctx, tt.history)

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

func TestFamilyHistoryRepository_DeleteFamilyHistory(t *testing.T) {
	ctx := context.Background()
	historyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   historyID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteFamilyHistory", ctx, uuidPgtypeFromString(historyID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   historyID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteFamilyHistory", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   historyID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteFamilyHistory", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewFamilyHistoryRepositoryWithQuerier(mockQuerier)

			err := repo.DeleteFamilyHistory(ctx, tt.id)

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