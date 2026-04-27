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

func TestMedicalInfoRepository_CreateMedicalInfo(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	infoID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	bloodType := "O+"
	organDonor := true
	advanceDirectiveExists := false
	dnrStatus := false

	tests := []struct {
		name       string
		info       patients.PatientMedicalInfo
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			info: patients.PatientMedicalInfo{
				PatientID:             patientID,
				BloodType:             &bloodType,
				OrganDonor:            organDonor,
				AdvanceDirectiveExists: advanceDirectiveExists,
				DNRStatus:             dnrStatus,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientMedicalInfo{
					ID:                       uuidPgtypeFromString(infoID.String()),
					PatientID:               uuidPgtypeFromString(patientID.String()),
					BloodType:               pgtype.Text{String: "O+", Valid: true},
					OrganDonor:              pgtype.Bool{Bool: true, Valid: true},
					AdvanceDirectiveExists: pgtype.Bool{Bool: false, Valid: true},
					DnrStatus:               pgtype.Bool{Bool: false, Valid: true},
					CreatedAt:               pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:               pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreatePatientMedicalInfo", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			info: patients.PatientMedicalInfo{
				PatientID: patientID,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreatePatientMedicalInfo", ctx, mock.Anything).Return(sqlc.PatientMedicalInfo{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			info: patients.PatientMedicalInfo{
				PatientID: patientID,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreatePatientMedicalInfo", ctx, mock.Anything).Return(sqlc.PatientMedicalInfo{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicalInfoRepositoryWithQuerier(mockQuerier)

			gotInfo, err := repo.CreateMedicalInfo(ctx, tt.info)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "O+", *gotInfo.BloodType)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestMedicalInfoRepository_GetMedicalInfoByPatientID(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	infoID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

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
				expectedRow := sqlc.PatientMedicalInfo{
					ID:               uuidPgtypeFromString(infoID.String()),
					PatientID:        uuidPgtypeFromString(patientID.String()),
					BloodType:        pgtype.Text{String: "O+", Valid: true},
					OrganDonor:       pgtype.Bool{Bool: true, Valid: true},
					CreatedAt:        pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:        pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetPatientMedicalInfo", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientMedicalInfo", ctx, uuidPgtypeFromString(patientID.String())).Return(sqlc.PatientMedicalInfo{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientMedicalInfo", ctx, mock.Anything).Return(sqlc.PatientMedicalInfo{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicalInfoRepositoryWithQuerier(mockQuerier)

			gotInfo, err := repo.GetMedicalInfoByPatientID(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "O+", *gotInfo.BloodType)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestMedicalInfoRepository_UpdateMedicalInfo(t *testing.T) {
	ctx := context.Background()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	bloodType := "A+"

	tests := []struct {
		name       string
		info       patients.PatientMedicalInfo
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			info: patients.PatientMedicalInfo{
				PatientID: patientID,
				BloodType: &bloodType,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientMedicalInfo", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			info: patients.PatientMedicalInfo{
				PatientID: patientID,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientMedicalInfo", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			info: patients.PatientMedicalInfo{
				PatientID: patientID,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientMedicalInfo", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicalInfoRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateMedicalInfo(ctx, tt.info)

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

func TestMedicalInfoRepository_DeleteMedicalInfoByPatientID(t *testing.T) {
	ctx := context.Background()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

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
				m.On("DeletePatientMedicalInfo", ctx, uuidPgtypeFromString(patientID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientMedicalInfo", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientMedicalInfo", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewMedicalInfoRepositoryWithQuerier(mockQuerier)

			err := repo.DeleteMedicalInfoByPatientID(ctx, tt.patientID)

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