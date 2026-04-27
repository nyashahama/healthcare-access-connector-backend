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

func TestDependentRepository_AddPatientDependent(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	dependentID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		dependent  patients.PatientDependent
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			dependent: patients.PatientDependent{
				PatientID:    patientID,
				FirstName:    "John",
				LastName:     "Doe",
				DateOfBirth:  now,
				Relationship: "Child",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientDependent{
					ID:           uuidPgtypeFromString(dependentID.String()),
					PatientID:   uuidPgtypeFromString(patientID.String()),
					FirstName:   "John",
					LastName:    "Doe",
					DateOfBirth: pgtype.Date{Time: now, Valid: true},
					Relationship: "Child",
					CreatedAt:   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddPatientDependent", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			dependent: patients.PatientDependent{
				PatientID:   patientID,
				FirstName:   "John",
				LastName:    "Doe",
				DateOfBirth: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientDependent", ctx, mock.Anything).Return(sqlc.PatientDependent{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			dependent: patients.PatientDependent{
				PatientID:   patientID,
				FirstName:   "John",
				LastName:    "Doe",
				DateOfBirth: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientDependent", ctx, mock.Anything).Return(sqlc.PatientDependent{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewDependentRepositoryWithQuerier(mockQuerier)

			gotDependent, err := repo.AddPatientDependent(ctx, tt.dependent)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "John", gotDependent.FirstName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestDependentRepository_GetPatientDependents(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	dependentID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

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
				expectedRows := []sqlc.GetPatientDependentsRow{
					{
						ID:            uuidPgtypeFromString(dependentID.String()),
						PatientID:     uuidPgtypeFromString(patientID.String()),
						FirstName:     "John",
						LastName:      "Doe",
						DateOfBirth:   pgtype.Date{Time: now, Valid: true},
						Relationship:  "Child",
						CreatedAt:     pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:     pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientDependents", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientDependents", ctx, uuidPgtypeFromString(patientID.String())).Return([]sqlc.GetPatientDependentsRow{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientDependents", ctx, mock.Anything).Return([]sqlc.GetPatientDependentsRow{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewDependentRepositoryWithQuerier(mockQuerier)

			gotDependents, err := repo.GetPatientDependents(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotDependents, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestDependentRepository_UpdatePatientDependent(t *testing.T) {
	ctx := context.Background()
	dependentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	now := nowTime()

	tests := []struct {
		name       string
		dependent  patients.PatientDependent
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			dependent: patients.PatientDependent{
				ID:         dependentID,
				FirstName:  "John",
				LastName:   "Doe",
				DateOfBirth: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientDependent", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			dependent: patients.PatientDependent{
				ID:         dependentID,
				FirstName:  "John",
				LastName:   "Doe",
				DateOfBirth: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientDependent", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			dependent: patients.PatientDependent{
				ID:         dependentID,
				FirstName:  "John",
				LastName:   "Doe",
				DateOfBirth: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientDependent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewDependentRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientDependent(ctx, tt.dependent)

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

func TestDependentRepository_DeletePatientDependent(t *testing.T) {
	ctx := context.Background()
	dependentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   dependentID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientDependent", ctx, uuidPgtypeFromString(dependentID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   dependentID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientDependent", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   dependentID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientDependent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewDependentRepositoryWithQuerier(mockQuerier)

			err := repo.DeletePatientDependent(ctx, tt.id)

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