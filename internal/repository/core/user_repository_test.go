package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestUserRepository_GetUserByID(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedError error
	}{
		{
			name: "successful get user by ID with email",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByIDRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 75, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
				}
				m.On("GetUserByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   userID,
				Email:                stringPtr("test@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           5,
				IsSMSOnly:            false,
				ProfileCompletionPct: 75,
				CreatedAt:            now.Add(-time.Hour * 24 * 7),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedError: nil,
		},
		{
			name: "successful get user by ID with phone",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByIDRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					Role:                        "doctor",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 2), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 10, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 30), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
				}
				m.On("GetUserByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   userID,
				Email:                nil,
				Phone:                stringPtr("+1234567890"),
				Role:                 "doctor",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            timePtr(now.Add(-time.Hour * 2)),
				LoginCount:           10,
				IsSMSOnly:            true,
				ProfileCompletionPct: 100,
				CreatedAt:            now.Add(-time.Hour * 24 * 30),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedError: nil,
		},
		{
			name: "user not found",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.GetUserByIDRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "database error",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByID", ctx, mock.Anything).Return(sqlc.GetUserByIDRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedError: fmt.Errorf("get user by id: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			gotUser, err := repo.GetUserByID(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == domain.ErrUserNotFound {
					assert.Equal(t, domain.ErrUserNotFound, err)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
				assertUserEqual(t, tt.expectedUser, gotUser)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUser(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		user          core.User
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful update user with all fields",
			user: core.User{
				ID:                   userID,
				Email:                stringPtr("updated@example.com"),
				Phone:                stringPtr("+1234567890"),
				Role:                 "doctor",
				Status:               "active",
				IsSMSOnly:            false,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ConsentDate:          &now,
				ProfileCompletionPct: 90,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUser", ctx, sqlc.UpdateUserParams{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "updated@example.com",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					Role:                        "doctor",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ConsentDate:                 pgtype.Timestamp{Time: now, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 90, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "successful update user with nil email and phone",
			user: core.User{
				ID:                   userID,
				Email:                nil,
				Phone:                nil,
				Role:                 "patient",
				Status:               "pending",
				IsSMSOnly:            true,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    false,
				ConsentDate:          nil,
				ProfileCompletionPct: 0,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUser", ctx, sqlc.UpdateUserParams{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "",
					Phone:                       pgtype.Text{Valid: false},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "pending", Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: false, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: false, Valid: true},
					ConsentDate:                 pgtype.Timestamp{Valid: false},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			user: core.User{
				ID:   userID,
				Role: "patient",
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUser", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUser(ctx, tt.user)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_DeactivateUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful deactivate user",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserStatus", ctx, sqlc.UpdateUserStatusParams{
					ID:     uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Status: pgtype.Text{String: "inactive", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserStatus", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("deactivate user: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.DeactivateUser(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_DeleteUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful delete user",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteUser", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteUser", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("delete user: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.DeleteUser(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_ListUsers(t *testing.T) {
	ctx := context.Background()
	now := nowTime()

	tests := []struct {
		name          string
		role          string
		limit         int
		offset        int
		mockSetup     func(*mocks.Querier)
		expectedUsers []core.User
		expectedError error
	}{
		{
			name:   "successful list users by role",
			role:   "patient",
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.ListUsersByRoleRow{
					{
						ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
						Email:                       "patient1@example.com",
						Phone:                       pgtype.Text{Valid: false},
						Role:                        "patient",
						Status:                      pgtype.Text{String: "active", Valid: true},
						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
						LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
						ProfileCompletionPercentage: pgtype.Int4{Int32: 80, Valid: true},
						CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
					},
					{
						ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174002"),
						Email:                       "",
						Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
						Role:                        "patient",
						Status:                      pgtype.Text{String: "pending", Valid: true},
						IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
						LastLogin:                   pgtype.Timestamp{Valid: false},
						ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
						CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24), Valid: true},
					},
				}
				m.On("ListUsersByRole", ctx, sqlc.ListUsersByRoleParams{
					Role:   "patient",
					Limit:  int32(10),
					Offset: int32(0),
				}).Return(expectedRows, nil)
			},
			expectedUsers: []core.User{
				{
					ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
					Email:                stringPtr("patient1@example.com"),
					Phone:                nil,
					Role:                 "patient",
					Status:               "active",
					IsVerified:           true,
					LastLogin:            timePtr(now.Add(-time.Hour)),
					LoginCount:           0,     // Not returned in list query
					IsSMSOnly:            false, // Not returned in list query
					ProfileCompletionPct: 80,
					CreatedAt:            now.Add(-time.Hour * 24 * 7),
				},
				{
					ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
					Email:                nil,
					Phone:                stringPtr("+1234567890"),
					Role:                 "patient",
					Status:               "pending",
					IsVerified:           false,
					LastLogin:            nil,
					LoginCount:           0,
					IsSMSOnly:            false,
					ProfileCompletionPct: 0,
					CreatedAt:            now.Add(-time.Hour * 24),
				},
			},
			expectedError: nil,
		},
		{
			name:   "empty result",
			role:   "doctor",
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				m.On("ListUsersByRole", ctx, sqlc.ListUsersByRoleParams{
					Role:   "doctor",
					Limit:  int32(10),
					Offset: int32(0),
				}).Return([]sqlc.ListUsersByRoleRow{}, nil)
			},
			expectedUsers: []core.User{},
			expectedError: nil,
		},
		{
			name:   "database error",
			role:   "patient",
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				m.On("ListUsersByRole", ctx, mock.Anything).Return([]sqlc.ListUsersByRoleRow{}, assert.AnError)
			},
			expectedUsers: nil,
			expectedError: fmt.Errorf("list users: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			gotUsers, err := repo.ListUsers(ctx, tt.role, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotUsers)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedUsers), len(gotUsers))
				for i, expectedUser := range tt.expectedUsers {
					assertUserEqual(t, expectedUser, gotUsers[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_SearchUsers(t *testing.T) {
	ctx := context.Background()
	now := nowTime()

	tests := []struct {
		name          string
		query         string
		role          string
		status        string
		mockSetup     func(*mocks.Querier)
		expectedUsers []core.User
		expectedError error
	}{
		{
			name:   "successful search users by email",
			query:  "test@example.com",
			role:   "",
			status: "",
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.SearchUsersRow{
					{
						ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
						Email:                       "test@example.com",
						Phone:                       pgtype.Text{Valid: false},
						Role:                        "patient",
						Status:                      pgtype.Text{String: "active", Valid: true},
						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
						LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
						ProfileCompletionPercentage: pgtype.Int4{Int32: 90, Valid: true},
						CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
					},
				}
				m.On("SearchUsers", ctx, sqlc.SearchUsersParams{
					Column1: "test@example.com",
					Column2: "",
					Column3: "",
				}).Return(expectedRows, nil)
			},
			expectedUsers: []core.User{
				{
					ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
					Email:                stringPtr("test@example.com"),
					Phone:                nil,
					Role:                 "patient",
					Status:               "active",
					IsVerified:           true,
					LastLogin:            timePtr(now.Add(-time.Hour)),
					LoginCount:           0,
					IsSMSOnly:            false,
					ProfileCompletionPct: 90,
					CreatedAt:            now.Add(-time.Hour * 24 * 7),
				},
			},
			expectedError: nil,
		},
		{
			name:   "successful search users with role filter",
			query:  "",
			role:   "doctor",
			status: "active",
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.SearchUsersRow{
					{
						ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174002"),
						Email:                       "doctor@example.com",
						Phone:                       pgtype.Text{Valid: false},
						Role:                        "doctor",
						Status:                      pgtype.Text{String: "active", Valid: true},
						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
						LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 2), Valid: true},
						ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
						CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 30), Valid: true},
					},
				}
				m.On("SearchUsers", ctx, sqlc.SearchUsersParams{
					Column1: "",
					Column2: "doctor",
					Column3: "active",
				}).Return(expectedRows, nil)
			},
			expectedUsers: []core.User{
				{
					ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
					Email:                stringPtr("doctor@example.com"),
					Phone:                nil,
					Role:                 "doctor",
					Status:               "active",
					IsVerified:           true,
					LastLogin:            timePtr(now.Add(-time.Hour * 2)),
					LoginCount:           0,
					IsSMSOnly:            false,
					ProfileCompletionPct: 100,
					CreatedAt:            now.Add(-time.Hour * 24 * 30),
				},
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			query:  "test",
			role:   "",
			status: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("SearchUsers", ctx, mock.Anything).Return([]sqlc.SearchUsersRow{}, assert.AnError)
			},
			expectedUsers: nil,
			expectedError: fmt.Errorf("search users: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			gotUsers, err := repo.SearchUsers(ctx, tt.query, tt.role, tt.status)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotUsers)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedUsers), len(gotUsers))
				for i, expectedUser := range tt.expectedUsers {
					assertUserEqual(t, expectedUser, gotUsers[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_CountUsers(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		role          string
		mockSetup     func(*mocks.Querier)
		expectedCount int64
		expectedError error
	}{
		{
			name: "successful count users by role",
			role: "patient",
			mockSetup: func(m *mocks.Querier) {
				m.On("CountUsersByRole", ctx, "patient").Return(int64(42), nil)
			},
			expectedCount: 42,
			expectedError: nil,
		},
		{
			name: "zero users",
			role: "doctor",
			mockSetup: func(m *mocks.Querier) {
				m.On("CountUsersByRole", ctx, "doctor").Return(int64(0), nil)
			},
			expectedCount: 0,
			expectedError: nil,
		},
		{
			name: "database error",
			role: "patient",
			mockSetup: func(m *mocks.Querier) {
				m.On("CountUsersByRole", ctx, mock.Anything).Return(int64(0), assert.AnError)
			},
			expectedCount: 0,
			expectedError: fmt.Errorf("count users: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			gotCount, err := repo.CountUsers(ctx, tt.role)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Equal(t, tt.expectedCount, gotCount)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, gotCount)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_GetUserProfile(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name            string
		userID          uuid.UUID
		mockSetup       func(*mocks.Querier)
		expectedUser    core.User
		expectedProfile patients.PatientProfile
		expectedError   error
	}{
		{
			name:   "successful get user profile",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				// Mock GetUserByID call
				userRow := sqlc.GetUserByIDRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 75, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
				}
				m.On("GetUserByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(userRow, nil)
			},
			expectedUser: core.User{
				ID:                   userID,
				Email:                stringPtr("test@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           5,
				IsSMSOnly:            false,
				ProfileCompletionPct: 75,
				CreatedAt:            now.Add(-time.Hour * 24 * 7),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedProfile: patients.PatientProfile{},
			expectedError:   nil,
		},
		{
			name:   "user not found",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.GetUserByIDRow{}, pgx.ErrNoRows)
			},
			expectedUser:    core.User{},
			expectedProfile: patients.PatientProfile{},
			expectedError:   domain.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			gotUser, gotProfile, err := repo.GetUserProfile(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Equal(t, domain.ErrUserNotFound, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedProfile, gotProfile)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedProfile, gotProfile)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUserEmail(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		email         string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:  "successful update user email",
			id:    userID,
			email: "newemail@example.com",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserEmail", ctx, sqlc.UpdateUserEmailParams{
					ID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email: "newemail@example.com",
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:  "empty email",
			id:    userID,
			email: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserEmail", ctx, sqlc.UpdateUserEmailParams{
					ID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email: "",
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:  "database error",
			id:    userID,
			email: "test@example.com",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserEmail", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user email: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUserEmail(ctx, tt.id, tt.email)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUserPhone(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		phone         string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:  "successful update user phone",
			id:    userID,
			phone: "+1234567890",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPhone", ctx, sqlc.UpdateUserPhoneParams{
					ID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Phone: pgtype.Text{String: "+1234567890", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:  "empty phone",
			id:    userID,
			phone: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPhone", ctx, sqlc.UpdateUserPhoneParams{
					ID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Phone: pgtype.Text{String: "", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:  "database error",
			id:    userID,
			phone: "+1234567890",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPhone", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user phone: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUserPhone(ctx, tt.id, tt.phone)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUserRole(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		role          string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful update user role",
			id:   userID,
			role: "doctor",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserRole", ctx, sqlc.UpdateUserRoleParams{
					ID:   uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Role: "doctor",
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			id:   userID,
			role: "doctor",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserRole", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user role: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUserRole(ctx, tt.id, tt.role)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUserStatus(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		status        string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful update user status to active",
			id:     userID,
			status: "active",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserStatus", ctx, sqlc.UpdateUserStatusParams{
					ID:     uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Status: pgtype.Text{String: "active", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "successful update user status to suspended",
			id:     userID,
			status: "suspended",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserStatus", ctx, sqlc.UpdateUserStatusParams{
					ID:     uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Status: pgtype.Text{String: "suspended", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			id:     userID,
			status: "active",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserStatus", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user status: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUserStatus(ctx, tt.id, tt.status)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUserProfileCompletion(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		percentage    int
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:       "successful update user profile completion",
			id:         userID,
			percentage: 75,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserProfileCompletion", ctx, sqlc.UpdateUserProfileCompletionParams{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ProfileCompletionPercentage: pgtype.Int4{Int32: 75, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:       "update to 100% completion",
			id:         userID,
			percentage: 100,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserProfileCompletion", ctx, sqlc.UpdateUserProfileCompletionParams{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:       "database error",
			id:         userID,
			percentage: 50,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserProfileCompletion", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user profile completion: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUserProfileCompletion(ctx, tt.id, tt.percentage)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_UpdateUserConsents(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		smsConsent    bool
		popiaConsent  bool
		consentDate   time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:         "successful update user consents",
			id:           userID,
			smsConsent:   true,
			popiaConsent: true,
			consentDate:  now,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserConsents", ctx, sqlc.UpdateUserConsentsParams{
					ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SmsConsentGiven:   pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven: pgtype.Bool{Bool: true, Valid: true},
					ConsentDate:       pgtype.Timestamp{Time: now, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "update consents to false",
			id:           userID,
			smsConsent:   false,
			popiaConsent: false,
			consentDate:  now,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserConsents", ctx, sqlc.UpdateUserConsentsParams{
					ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SmsConsentGiven:   pgtype.Bool{Bool: false, Valid: true},
					PopiaConsentGiven: pgtype.Bool{Bool: false, Valid: true},
					ConsentDate:       pgtype.Timestamp{Time: now, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "database error",
			id:           userID,
			smsConsent:   true,
			popiaConsent: true,
			consentDate:  now,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserConsents", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update user consents: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.UpdateUserConsents(ctx, tt.id, tt.smsConsent, tt.popiaConsent, tt.consentDate)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_BulkUpdateStatus(t *testing.T) {
	ctx := context.Background()
	userIDs := []uuid.UUID{
		uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
		uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
		uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
	}

	tests := []struct {
		name          string
		ids           []uuid.UUID
		status        string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful bulk update status",
			ids:    userIDs,
			status: "suspended",
			mockSetup: func(m *mocks.Querier) {
				pgIDs := make([]pgtype.UUID, len(userIDs))
				for i, id := range userIDs {
					pgIDs[i] = uuidPgtypeFromString(id.String())
				}
				m.On("BulkUpdateUserStatus", ctx, sqlc.BulkUpdateUserStatusParams{
					Column1: pgIDs,
					Status:  pgtype.Text{String: "suspended", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "empty ids list",
			ids:    []uuid.UUID{},
			status: "active",
			mockSetup: func(m *mocks.Querier) {
				m.On("BulkUpdateUserStatus", ctx, sqlc.BulkUpdateUserStatusParams{
					Column1: []pgtype.UUID{},
					Status:  pgtype.Text{String: "active", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			ids:    userIDs,
			status: "suspended",
			mockSetup: func(m *mocks.Querier) {
				m.On("BulkUpdateUserStatus", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("bulk update status: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			err := repo.BulkUpdateStatus(ctx, tt.ids, tt.status)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestUserRepository_GetUsersByIDs(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	userIDs := []uuid.UUID{
		uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
		uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
	}

	tests := []struct {
		name          string
		ids           []uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedUsers []core.User
		expectedError error
	}{
		{
			name: "successful get users by IDs",
			ids:  userIDs,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.GetUsersByIDsRow{
					{
						ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
						Email:                       "user1@example.com",
						Phone:                       pgtype.Text{Valid: false},
						Role:                        "patient",
						Status:                      pgtype.Text{String: "active", Valid: true},
						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
						LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
						LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
						IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
						ProfileCompletionPercentage: pgtype.Int4{Int32: 80, Valid: true},
						CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
						UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					},
					{
						ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174002"),
						Email:                       "",
						Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
						Role:                        "doctor",
						Status:                      pgtype.Text{String: "active", Valid: true},
						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
						LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 2), Valid: true},
						LoginCount:                  pgtype.Int4{Int32: 10, Valid: true},
						IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
						ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
						CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 30), Valid: true},
						UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					},
				}
				pgIDs := make([]pgtype.UUID, len(userIDs))
				for i, id := range userIDs {
					pgIDs[i] = uuidPgtypeFromString(id.String())
				}
				m.On("GetUsersByIDs", ctx, pgIDs).Return(expectedRows, nil)
			},
			expectedUsers: []core.User{
				{
					ID:                   userIDs[0],
					Email:                stringPtr("user1@example.com"),
					Phone:                nil,
					Role:                 "patient",
					Status:               "active",
					IsVerified:           true,
					LastLogin:            timePtr(now.Add(-time.Hour)),
					LoginCount:           5,
					IsSMSOnly:            false,
					ProfileCompletionPct: 80,
					CreatedAt:            now.Add(-time.Hour * 24 * 7),
					UpdatedAt:            now.Add(-time.Hour),
				},
				{
					ID:                   userIDs[1],
					Email:                nil,
					Phone:                stringPtr("+1234567890"),
					Role:                 "doctor",
					Status:               "active",
					IsVerified:           true,
					LastLogin:            timePtr(now.Add(-time.Hour * 2)),
					LoginCount:           10,
					IsSMSOnly:            true,
					ProfileCompletionPct: 100,
					CreatedAt:            now.Add(-time.Hour * 24 * 30),
					UpdatedAt:            now.Add(-time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name: "empty IDs list",
			ids:  []uuid.UUID{},
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUsersByIDs", ctx, []pgtype.UUID{}).Return([]sqlc.GetUsersByIDsRow{}, nil)
			},
			expectedUsers: []core.User{},
			expectedError: nil,
		},
		{
			name: "database error",
			ids:  userIDs,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUsersByIDs", ctx, mock.Anything).Return([]sqlc.GetUsersByIDsRow{}, assert.AnError)
			},
			expectedUsers: nil,
			expectedError: fmt.Errorf("get users by ids: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &userRepository{querier: mockQuerier}

			gotUsers, err := repo.GetUsersByIDs(ctx, tt.ids)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotUsers)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedUsers), len(gotUsers))
				for i, expectedUser := range tt.expectedUsers {
					assertUserEqual(t, expectedUser, gotUsers[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
