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

func TestSurgeryRepository_AddPatientSurgery(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	surgeryID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		surgery    patients.PatientSurgery
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			surgery: patients.PatientSurgery{
				PatientID:     patientID,
				ProcedureName: "Appendectomy",
				ProcedureDate: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientSurgery{
					ID:             uuidPgtypeFromString(surgeryID.String()),
					PatientID:      uuidPgtypeFromString(patientID.String()),
					ProcedureName:  "Appendectomy",
					ProcedureDate:  pgtype.Date{Time: now, Valid: true},
					CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:      pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddPatientSurgery", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			surgery: patients.PatientSurgery{
				PatientID:     patientID,
				ProcedureName: "Appendectomy",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientSurgery", ctx, mock.Anything).Return(sqlc.PatientSurgery{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			surgery: patients.PatientSurgery{
				PatientID:     patientID,
				ProcedureName: "Appendectomy",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientSurgery", ctx, mock.Anything).Return(sqlc.PatientSurgery{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSurgeryRepositoryWithQuerier(mockQuerier)

			gotSurgery, err := repo.AddPatientSurgery(ctx, tt.surgery)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Appendectomy", gotSurgery.ProcedureName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestSurgeryRepository_GetPatientSurgeries(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	surgeryID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

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
				expectedRows := []sqlc.PatientSurgery{
					{
						ID:             uuidPgtypeFromString(surgeryID.String()),
						PatientID:      uuidPgtypeFromString(patientID.String()),
						ProcedureName:  "Appendectomy",
						ProcedureDate:  pgtype.Date{Time: now, Valid: true},
						CreatedAt:      pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:      pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientSurgeries", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientSurgeries", ctx, uuidPgtypeFromString(patientID.String())).Return([]sqlc.PatientSurgery{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientSurgeries", ctx, mock.Anything).Return([]sqlc.PatientSurgery{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSurgeryRepositoryWithQuerier(mockQuerier)

			gotSurgeries, err := repo.GetPatientSurgeries(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotSurgeries, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestSurgeryRepository_UpdatePatientSurgery(t *testing.T) {
	ctx := context.Background()
	surgeryID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	now := nowTime()

	tests := []struct {
		name       string
		surgery    patients.PatientSurgery
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			surgery: patients.PatientSurgery{
				ID:            surgeryID,
				ProcedureName: "Appendectomy",
				ProcedureDate: now,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientSurgery", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			surgery: patients.PatientSurgery{
				ID:            surgeryID,
				ProcedureName: "Appendectomy",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientSurgery", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			surgery: patients.PatientSurgery{
				ID:            surgeryID,
				ProcedureName: "Appendectomy",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientSurgery", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSurgeryRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientSurgery(ctx, tt.surgery)

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

func TestSurgeryRepository_DeletePatientSurgery(t *testing.T) {
	ctx := context.Background()
	surgeryID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   surgeryID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientSurgery", ctx, uuidPgtypeFromString(surgeryID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   surgeryID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientSurgery", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   surgeryID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientSurgery", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSurgeryRepositoryWithQuerier(mockQuerier)

			err := repo.DeletePatientSurgery(ctx, tt.id)

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