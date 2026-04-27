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

func TestConditionRepository_AddPatientCondition(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	conditionID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	status := "Active"

	tests := []struct {
		name       string
		condition  patients.PatientCondition
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			condition: patients.PatientCondition{
				PatientID:     patientID,
				ConditionName: "Diabetes",
				Status:        status,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientCondition{
					ID:              uuidPgtypeFromString(conditionID.String()),
					PatientID:      uuidPgtypeFromString(patientID.String()),
					ConditionName:  "Diabetes",
					Status:          pgtype.Text{String: status, Valid: true},
					CreatedAt:       pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:       pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddPatientCondition", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			condition: patients.PatientCondition{
				PatientID:     patientID,
				ConditionName: "Diabetes",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientCondition", ctx, mock.Anything).Return(sqlc.PatientCondition{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			condition: patients.PatientCondition{
				PatientID:     patientID,
				ConditionName: "Diabetes",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientCondition", ctx, mock.Anything).Return(sqlc.PatientCondition{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConditionRepositoryWithQuerier(mockQuerier)

			gotCondition, err := repo.AddPatientCondition(ctx, tt.condition)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Diabetes", gotCondition.ConditionName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConditionRepository_GetPatientConditions(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	conditionID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
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
				expectedRows := []sqlc.PatientCondition{
					{
						ID:              uuidPgtypeFromString(conditionID.String()),
						PatientID:      uuidPgtypeFromString(patientID.String()),
						ConditionName:  "Diabetes",
						Status:          pgtype.Text{String: status, Valid: true},
						CreatedAt:       pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:       pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientConditions", ctx, mock.Anything).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			status:    &status,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientConditions", ctx, mock.Anything).Return([]sqlc.PatientCondition{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			status:    &status,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientConditions", ctx, mock.Anything).Return([]sqlc.PatientCondition{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConditionRepositoryWithQuerier(mockQuerier)

			gotConditions, err := repo.GetPatientConditions(ctx, tt.patientID, tt.status)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotConditions, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConditionRepository_UpdatePatientCondition(t *testing.T) {
	ctx := context.Background()
	conditionID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		condition  patients.PatientCondition
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			condition: patients.PatientCondition{
				ID:              conditionID,
				ConditionName:   "Diabetes",
				Status:          "Resolved",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientCondition", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			condition: patients.PatientCondition{
				ID:              conditionID,
				ConditionName:   "Diabetes",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientCondition", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			condition: patients.PatientCondition{
				ID:              conditionID,
				ConditionName:   "Diabetes",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientCondition", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConditionRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientCondition(ctx, tt.condition)

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

func TestConditionRepository_DeletePatientCondition(t *testing.T) {
	ctx := context.Background()
	conditionID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   conditionID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientCondition", ctx, uuidPgtypeFromString(conditionID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   conditionID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientCondition", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   conditionID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientCondition", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConditionRepositoryWithQuerier(mockQuerier)

			err := repo.DeletePatientCondition(ctx, tt.id)

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