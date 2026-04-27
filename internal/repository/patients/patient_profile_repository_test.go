package patients

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func uuidPgtypeFromString(s string) pgtype.UUID {
	return pgtype.UUID{Bytes: uuid.MustParse(s), Valid: true}
}

func nowTime() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func stringPtr(s string) *string {
	return &s
}

func TestPatientProfileRepository_CreatePatientProfile(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	userID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		profile      patients.PatientProfile
		mockSetup    func(*mocks.MockQuerier)
		expectError bool
		errContains string
	}{
		{
			name: "successful create patient profile",
			profile: patients.PatientProfile{
				ID:     patientID,
				UserID:  userID,
				FirstName: "John",
				LastName:  "Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientProfile{
					ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					UserID:            uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					FirstName:         "John",
					LastName:          "Doe",
					LanguagePreferences: []string{"English"},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreatePatientProfile", ctx, mock.MatchedBy(func(params sqlc.CreatePatientProfileParams) bool {
					return params.FirstName == "John" && params.LastName == "Doe"
				})).Return(expectedRow, nil)
			},
			expectError: false,
			errContains: "",
		},
		{
			name: "database error",
			profile: patients.PatientProfile{
				UserID:     userID,
				FirstName:  "John",
				LastName:   "Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreatePatientProfile", ctx, mock.Anything).Return(sqlc.PatientProfile{}, assert.AnError)
			},
			expectError: true,
			errContains: "",
		},
		{
			name: "duplicate national ID",
			profile: patients.PatientProfile{
				UserID:           userID,
				FirstName:        "John",
				LastName:         "Doe",
				NationalIDNumber: stringPtr("123456789"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{
					Code:          "23505",
					ConstraintName: "patient_profiles_national_id_number_key",
				}
				m.On("CreatePatientProfile", ctx, mock.Anything).Return(sqlc.PatientProfile{}, pgErr)
			},
			expectError: true,
			errContains: "already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewPatientRepositoryWithQuerier(mockQuerier)

			gotProfile, err := repo.CreatePatientProfile(ctx, tt.profile)

			if tt.expectError {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "John", gotProfile.FirstName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestPatientProfileRepository_GetPatientProfileByID(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedProfile patients.PatientProfile
		expectError    bool
		errIsNotFound  bool
	}{
		{
			name: "found",
			id:   patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientProfile{
					ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					UserID:            uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					FirstName:         "John",
					LastName:          "Doe",
					LanguagePreferences: []string{"English"},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetPatientProfileByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRow, nil)
			},
			expectedProfile: patients.PatientProfile{
				ID:            patientID,
				FirstName:     "John",
				LastName:      "Doe",
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			expectError:   false,
			errIsNotFound: false,
		},
		{
			name: "not found",
			id:   patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientProfileByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.PatientProfile{}, pgx.ErrNoRows)
			},
			expectedProfile: patients.PatientProfile{},
			expectError:     true,
			errIsNotFound:   true,
		},
		{
			name: "database error",
			id:   patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientProfileByID", ctx, mock.Anything).Return(sqlc.PatientProfile{}, assert.AnError)
			},
			expectedProfile: patients.PatientProfile{},
			expectError:      true,
			errIsNotFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewPatientRepositoryWithQuerier(mockQuerier)

			gotProfile, err := repo.GetPatientProfileByID(ctx, tt.id)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
				assert.Equal(t, tt.expectedProfile, gotProfile)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedProfile.ID, gotProfile.ID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestPatientProfileRepository_GetPatientProfileByUserID(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedProfile patients.PatientProfile
		expectError    bool
		errIsNotFound  bool
	}{
		{
			name:   "found",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.PatientProfile{
					ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					UserID:            uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					FirstName:         "John",
					LastName:          "Doe",
					LanguagePreferences: []string{"English"},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetPatientProfileByUserID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRow, nil)
			},
			expectedProfile: patients.PatientProfile{
				UserID:    userID,
				FirstName: "John",
				LastName:  "Doe",
				CreatedAt: now,
				UpdatedAt: now,
			},
			expectError:   false,
			errIsNotFound: false,
		},
		{
			name:   "not found",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientProfileByUserID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.PatientProfile{}, pgx.ErrNoRows)
			},
			expectedProfile: patients.PatientProfile{},
			expectError:     true,
			errIsNotFound:   true,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientProfileByUserID", ctx, mock.Anything).Return(sqlc.PatientProfile{}, assert.AnError)
			},
			expectedProfile: patients.PatientProfile{},
			expectError:      true,
			errIsNotFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewPatientRepositoryWithQuerier(mockQuerier)

			gotProfile, err := repo.GetPatientProfileByUserID(ctx, tt.userID)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
				assert.Equal(t, tt.expectedProfile, gotProfile)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedProfile.UserID, gotProfile.UserID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestPatientProfileRepository_UpdatePatientProfile(t *testing.T) {
	ctx := context.Background()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		profile      patients.PatientProfile
		mockSetup    func(*mocks.MockQuerier)
		expectedErr error
	}{
		{
			name: "success",
			profile: patients.PatientProfile{
				ID:        patientID,
				FirstName: "John",
				LastName:  "Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientProfile", ctx, mock.Anything).Return(nil)
			},
			expectedErr: nil,
		},
		{
			name: "not found",
			profile: patients.PatientProfile{
				ID:        patientID,
				FirstName: "John",
				LastName:  "Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientProfile", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectedErr: pgx.ErrNoRows,
		},
		{
			name: "database error",
			profile: patients.PatientProfile{
				ID:        patientID,
				FirstName: "John",
				LastName:  "Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePatientProfile", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedErr: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewPatientRepositoryWithQuerier(mockQuerier)

			err := repo.UpdatePatientProfile(ctx, tt.profile)

			if tt.expectedErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestPatientProfileRepository_NationalIDExists(t *testing.T) {
	ctx := context.Background()
	nationalID := "123456789"

	tests := []struct {
		name          string
		nationalID    string
		mockSetup    func(*mocks.MockQuerier)
		expectedBool bool
		expectedErr error
	}{
		{
			name:       "true",
			nationalID: nationalID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CheckNationalIDExists", ctx, sqlc.CheckNationalIDExistsParams{
					NationalIDNumber: pgtype.Text{String: nationalID, Valid: true},
					Column2:          pgtype.UUID{Valid: false},
				}).Return(true, nil)
			},
			expectedBool: true,
			expectedErr:  nil,
		},
		{
			name:       "false",
			nationalID: nationalID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CheckNationalIDExists", ctx, sqlc.CheckNationalIDExistsParams{
					NationalIDNumber: pgtype.Text{String: nationalID, Valid: true},
					Column2:          pgtype.UUID{Valid: false},
				}).Return(false, nil)
			},
			expectedBool: false,
			expectedErr:  nil,
		},
		{
			name:       "database error",
			nationalID: nationalID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CheckNationalIDExists", ctx, mock.Anything).Return(false, assert.AnError)
			},
			expectedBool: false,
			expectedErr:  assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewPatientRepositoryWithQuerier(mockQuerier)

			gotBool, err := repo.NationalIDExists(ctx, tt.nationalID, nil)

			if tt.expectedErr != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBool, gotBool)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}