package telemedicine

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func buildAvailabilityRow(id, staffID string, isOnline, isAccepting bool) sqlc.ProviderAvailability {
	now := nowTime()
	return sqlc.ProviderAvailability{
		ID:                         uuidPgtypeFromString(id),
		StaffID:                    uuidPgtypeFromString(staffID),
		IsOnline:                   isOnline,
		IsAccepting:                isAccepting,
		Status:                     "available",
		ActiveConsultationCount:    0,
		MaxConcurrentConsultations: 3,
		EstimatedWaitMinutes:       pgtype.Int4{Valid: false},
		StatusMessage:              pgtype.Text{Valid: false},
		ConsultationFeeOverride:    pgtype.Numeric{Valid: false},
		LastSeenAt:                 pgtype.Timestamp{Valid: false},
		ShiftStart:                 pgtype.Timestamp{Valid: false},
		UpdatedAt:                 pgtype.Timestamp{Time: now, Valid: true},
	}
}

func buildAvailability(id string, staffID uuid.UUID, isOnline, isAccepting bool) telemedicine.ProviderAvailability {
	now := nowTime()
	return telemedicine.ProviderAvailability{
		ID:                         uuid.MustParse(id),
		StaffID:                    staffID,
		IsOnline:                   isOnline,
		IsAccepting:                isAccepting,
		Status:                     telemedicine.AvailabilityStatusAvailable,
		ActiveConsultationCount:    0,
		MaxConcurrentConsultations: 3,
		UpdatedAt:                  now,
	}
}

func TestProviderAvailabilityRepository_UpsertAvailability(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174003")

	tests := []struct {
		name          string
		staffID       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ProviderAvailability
		expectedError error
	}{
		{
			name:    "success",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildAvailabilityRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174003",
					false, false,
				)
				m.On("UpsertProviderAvailability", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(row, nil)
			},
			expected:      buildAvailability("123e4567-e89b-12d3-a456-426614174000", staffID, false, false),
			expectedError: nil,
		},
		{
			name:    "database error",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpsertProviderAvailability", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(sqlc.ProviderAvailability{}, assert.AnError)
			},
			expected:      telemedicine.ProviderAvailability{},
			expectedError: assert.AnError,
		},
		{
			name:    "not found",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpsertProviderAvailability", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(sqlc.ProviderAvailability{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ProviderAvailability{},
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewProviderAvailabilityRepositoryWithQuerier(mockQuerier)

			got, err := repo.UpsertAvailability(ctx, tt.staffID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "upsert availability")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.StaffID, got.StaffID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestProviderAvailabilityRepository_GoOnline(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174003")

	tests := []struct {
		name          string
		staffID       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ProviderAvailability
		expectedError error
	}{
		{
			name:    "success",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildAvailabilityRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174003",
					true, false,
				)
				row.ShiftStart = pgtype.Timestamp{Time: nowTime(), Valid: true}
				m.On("GoOnline", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(row, nil)
			},
			expected:      buildAvailability("123e4567-e89b-12d3-a456-426614174000", staffID, true, false),
			expectedError: nil,
		},
		{
			name:    "not found",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GoOnline", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(sqlc.ProviderAvailability{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ProviderAvailability{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:    "database error",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GoOnline", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(sqlc.ProviderAvailability{}, assert.AnError)
			},
			expected:      telemedicine.ProviderAvailability{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewProviderAvailabilityRepositoryWithQuerier(mockQuerier)

			got, err := repo.GoOnline(ctx, tt.staffID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "go online")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.True(t, got.IsOnline)
				assert.Equal(t, tt.expected.StaffID, got.StaffID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestProviderAvailabilityRepository_GoOffline(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174003")

	tests := []struct {
		name          string
		staffID       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name:    "success",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GoOffline", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "not found",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GoOffline", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(pgx.ErrNoRows)
			},
			expectedError: domain.ErrNotFound,
		},
		{
			name:    "database error",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GoOffline", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewProviderAvailabilityRepositoryWithQuerier(mockQuerier)

			err := repo.GoOffline(ctx, tt.staffID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "go offline")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestProviderAvailabilityRepository_SetAccepting(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174003")

	tests := []struct {
		name          string
		staffID       uuid.UUID
		accepting     bool
		feeOverride   *float64
		waitMinutes   *int
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ProviderAvailability
		expectedError error
	}{
		{
			name:        "success - accepting",
			staffID:     staffID,
			accepting:   true,
			feeOverride: nil,
			waitMinutes: intPtr(10),
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildAvailabilityRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174003",
					true, true,
				)
				row.EstimatedWaitMinutes = pgtype.Int4{Int32: 10, Valid: true}
				m.On("SetAccepting", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildAvailability("123e4567-e89b-12d3-a456-426614174000", staffID, true, true),
			expectedError: nil,
		},
		{
			name:        "success - not accepting",
			staffID:     staffID,
			accepting:   false,
			feeOverride: nil,
			waitMinutes: nil,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildAvailabilityRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174003",
					true, false,
				)
				m.On("SetAccepting", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildAvailability("123e4567-e89b-12d3-a456-426614174000", staffID, true, false),
			expectedError: nil,
		},
		{
			name:        "not found",
			staffID:     staffID,
			accepting:   true,
			feeOverride: nil,
			waitMinutes: nil,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("SetAccepting", ctx, mock.Anything).Return(sqlc.ProviderAvailability{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ProviderAvailability{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:        "database error",
			staffID:     staffID,
			accepting:   true,
			feeOverride: nil,
			waitMinutes: nil,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("SetAccepting", ctx, mock.Anything).Return(sqlc.ProviderAvailability{}, assert.AnError)
			},
			expected:      telemedicine.ProviderAvailability{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewProviderAvailabilityRepositoryWithQuerier(mockQuerier)

			got, err := repo.SetAccepting(ctx, tt.staffID, tt.accepting, tt.feeOverride, tt.waitMinutes)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "set accepting")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.IsAccepting, got.IsAccepting)
				assert.Equal(t, tt.expected.StaffID, got.StaffID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestProviderAvailabilityRepository_GetAvailableProviders(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		clinicID      *uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      []telemedicine.AvailableProvider
		expectedError error
	}{
		{
			name:     "found providers",
			clinicID: nil,
			mockSetup: func(m *mocks.MockQuerier) {
rows := []sqlc.GetAvailableProvidersRow{
					{
						StaffID:                    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003"),
						Status:                     "available",
						EstimatedWaitMinutes:       pgtype.Int4{Int32: 5, Valid: true},
						ActiveConsultationCount:    1,
						MaxConcurrentConsultations: 3,
						ConsultationFeeOverride:    pgtype.Numeric{Valid: false},
						StatusMessage:              pgtype.Text{Valid: false},
						Title:                      pgtype.Text{Valid: false},
						FirstName:                  "John",
						LastName:                   "Doe",
						ProfessionalTitle:         pgtype.Text{String: "Dr.", Valid: true},
						Specialization:             pgtype.Text{String: "General", Valid: true},
						Bio:                       pgtype.Text{Valid: false},
						ProfilePictureUrl:         pgtype.Text{Valid: false},
						YearsExperience:           pgtype.Int4{Valid: false},
						LanguagesSpoken:           []string{},
					},
				}
				m.On("GetAvailableProviders", ctx, pgtype.UUID{Valid: false}).Return(rows, nil)
			},
			expected: []telemedicine.AvailableProvider{
				{
					StaffID:                    uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
					Status:                     telemedicine.AvailabilityStatusAvailable,
					EstimatedWaitMinutes:       intPtr(5),
					ActiveConsultationCount:    1,
					MaxConcurrentConsultations: 3,
					FirstName:                  "John",
					LastName:                   "Doe",
					ProfessionalTitle:         stringPtr("Dr."),
					Specialization:             stringPtr("General"),
				},
			},
			expectedError: nil,
		},
		{
			name:     "empty",
			clinicID: nil,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAvailableProviders", ctx, pgtype.UUID{Valid: false}).Return([]sqlc.GetAvailableProvidersRow{}, nil)
			},
			expected:      []telemedicine.AvailableProvider{},
			expectedError: nil,
		},
		{
			name:     "database error",
			clinicID: nil,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAvailableProviders", ctx, pgtype.UUID{Valid: false}).Return(nil, assert.AnError)
			},
			expected:      nil,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewProviderAvailabilityRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetAvailableProviders(ctx, tt.clinicID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get available providers")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expected), len(got))
				if len(got) > 0 {
					assert.Equal(t, tt.expected[0].StaffID, got[0].StaffID)
					assert.Equal(t, tt.expected[0].FirstName, got[0].FirstName)
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}