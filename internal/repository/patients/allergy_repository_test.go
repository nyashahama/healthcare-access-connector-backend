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

func TestAllergyRepository_AddPatientAllergy(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	allergyID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		allergy    patients.PatientAllergy
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			allergy: patients.PatientAllergy{
				PatientID:   patientID,
				AllergyName: "Penicillin",
				Severity:    "Severe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientAllergy{
					ID:          uuidPgtypeFromString(allergyID.String()),
					PatientID:   uuidPgtypeFromString(patientID.String()),
					AllergyName: "Penicillin",
					Severity:    "Severe",
					Status:      pgtype.Text{String: "Active", Valid: true},
					CreatedAt:   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddPatientAllergy", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			allergy: patients.PatientAllergy{
				PatientID:   patientID,
				AllergyName: "Penicillin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientAllergy", ctx, mock.Anything).Return(sqlc.PatientAllergy{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			allergy: patients.PatientAllergy{
				PatientID:   patientID,
				AllergyName: "Penicillin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddPatientAllergy", ctx, mock.Anything).Return(sqlc.PatientAllergy{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAllergyRepositoryWithQuerier(mockQuerier)

			gotAllergy, err := repo.AddPatientAllergy(ctx, tt.allergy)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Penicillin", gotAllergy.AllergyName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAllergyRepository_GetPatientAllergies(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	allergyID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

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
				expectedRows := []sqlc.PatientAllergy{
					{
						ID:          uuidPgtypeFromString(allergyID.String()),
						PatientID:   uuidPgtypeFromString(patientID.String()),
						AllergyName: "Penicillin",
						Severity:    "Severe",
						Status:      pgtype.Text{String: "Active", Valid: true},
						CreatedAt:   pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:   pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientAllergies", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientAllergies", ctx, uuidPgtypeFromString(patientID.String())).Return([]sqlc.PatientAllergy{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientAllergies", ctx, mock.Anything).Return([]sqlc.PatientAllergy{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAllergyRepositoryWithQuerier(mockQuerier)

			gotAllergies, err := repo.GetPatientAllergies(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotAllergies, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAllergyRepository_UpdatePatientAllergy(t *testing.T) {
	ctx := context.Background()
	allergyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		allergy    patients.PatientAllergy
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			allergy: patients.PatientAllergy{
				ID:          allergyID,
				AllergyName: "Penicillin",
				Severity:    "Severe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientAllergy", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			allergy: patients.PatientAllergy{
				ID:          allergyID,
				AllergyName: "Penicillin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientAllergy", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			allergy: patients.PatientAllergy{
				ID:          allergyID,
				AllergyName: "Penicillin",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientAllergy", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAllergyRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientAllergy(ctx, tt.allergy)

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

func TestAllergyRepository_DeletePatientAllergy(t *testing.T) {
	ctx := context.Background()
	allergyID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   allergyID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientAllergy", ctx, uuidPgtypeFromString(allergyID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   allergyID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientAllergy", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   allergyID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeletePatientAllergy", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAllergyRepositoryWithQuerier(mockQuerier)

			err := repo.DeletePatientAllergy(ctx, tt.id)

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