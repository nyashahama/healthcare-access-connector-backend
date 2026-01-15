package core

//
// import (
// 	"context"
// 	"errors"
// 	"testing"
// 	"time"
//
// 	"github.com/google/uuid"
// 	"github.com/jackc/pgx/v5"
// 	"github.com/jackc/pgx/v5/pgtype"
// 	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
// 	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
// 	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
// 	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// 	"github.com/stretchr/testify/require"
// )
//
// // MockUserQuerier implements sqlc.Querier interface for user testing
// type MockUserQuerier struct {
// 	mock.Mock
// }
//
// func (m *MockUserQuerier) GetUserByID(ctx context.Context, id pgtype.UUID) (sqlc.GetUserByIDRow, error) {
// 	args := m.Called(ctx, id)
// 	return args.Get(0).(sqlc.GetUserByIDRow), args.Error(1)
// }
//
// func (m *MockUserQuerier) UpdateUser(ctx context.Context, params sqlc.UpdateUserParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) UpdateUserStatus(ctx context.Context, params sqlc.UpdateUserStatusParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) DeleteUser(ctx context.Context, id pgtype.UUID) error {
// 	args := m.Called(ctx, id)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) ListUsersByRole(ctx context.Context, params sqlc.ListUsersByRoleParams) ([]sqlc.ListUsersByRoleRow, error) {
// 	args := m.Called(ctx, params)
// 	return args.Get(0).([]sqlc.ListUsersByRoleRow), args.Error(1)
// }
//
// func (m *MockUserQuerier) SearchUsers(ctx context.Context, params sqlc.SearchUsersParams) ([]sqlc.SearchUsersRow, error) {
// 	args := m.Called(ctx, params)
// 	return args.Get(0).([]sqlc.SearchUsersRow), args.Error(1)
// }
//
// func (m *MockUserQuerier) CountUsersByRole(ctx context.Context, role string) (int64, error) {
// 	args := m.Called(ctx, role)
// 	return args.Get(0).(int64), args.Error(1)
// }
//
// func (m *MockUserQuerier) UpdateUserEmail(ctx context.Context, params sqlc.UpdateUserEmailParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) UpdateUserPhone(ctx context.Context, params sqlc.UpdateUserPhoneParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) UpdateUserRole(ctx context.Context, params sqlc.UpdateUserRoleParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) UpdateUserProfileCompletion(ctx context.Context, params sqlc.UpdateUserProfileCompletionParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) UpdateUserConsents(ctx context.Context, params sqlc.UpdateUserConsentsParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) BulkUpdateUserStatus(ctx context.Context, params sqlc.BulkUpdateUserStatusParams) error {
// 	args := m.Called(ctx, params)
// 	return args.Error(0)
// }
//
// func (m *MockUserQuerier) GetUsersByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.GetUsersByIDsRow, error) {
// 	args := m.Called(ctx, ids)
// 	return args.Get(0).([]sqlc.GetUsersByIDsRow), args.Error(1)
// }
//
// // Helper function to create SQLC user row
// func createTestUserRow(id uuid.UUID, email, phone string) sqlc.GetUserByIDRow {
// 	createdAt := time.Now()
// 	updatedAt := time.Now()
//
// 	return sqlc.GetUserByIDRow{
// 		ID:                          uuidToPgtypeUUID(id),
// 		Email:                       email,
// 		Phone:                       pgtype.Text{String: phone, Valid: phone != ""},
// 		Role:                        "patient",
// 		Status:                      pgtype.Text{String: "active", Valid: true},
// 		IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
// 		LastLogin:                   pgtype.Timestamp{Time: time.Now().Add(-1 * time.Hour), Valid: true},
// 		LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
// 		IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
// 		SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
// 		PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
// 		ProfileCompletionPercentage: pgtype.Int4{Int32: 75, Valid: true},
// 		CreatedAt:                   pgtype.Timestamp{Time: createdAt, Valid: true},
// 		UpdatedAt:                   pgtype.Timestamp{Time: updatedAt, Valid: true},
// 	}
// }
//
// func TestUserRepository_GetUserByID(t *testing.T) {
// 	userID := uuid.New()
//
// 	tests := []struct {
// 		name        string
// 		userID      uuid.UUID
// 		setupMock   func(*MockUserQuerier, uuid.UUID)
// 		wantErr     bool
// 		expectedErr error
// 	}{
// 		{
// 			name:   "successful user retrieval",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				m.On("GetUserByID", mock.Anything, uuidToPgtypeUUID(id)).
// 					Return(createTestUserRow(id, "test@example.com", "+1234567890"), nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:   "user not found",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				m.On("GetUserByID", mock.Anything, uuidToPgtypeUUID(id)).
// 					Return(sqlc.GetUserByIDRow{}, pgx.ErrNoRows)
// 			},
// 			wantErr:     true,
// 			expectedErr: domain.ErrUserNotFound,
// 		},
// 		{
// 			name:   "database error",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				m.On("GetUserByID", mock.Anything, uuidToPgtypeUUID(id)).
// 					Return(sqlc.GetUserByIDRow{}, errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			gotUser, err := repo.GetUserByID(ctx, tt.userID)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 				if tt.expectedErr != nil {
// 					assert.ErrorIs(t, err, tt.expectedErr)
// 				}
// 			} else {
// 				require.NoError(t, err)
// 				assert.Equal(t, tt.userID, gotUser.ID)
// 				assert.Equal(t, "test@example.com", *gotUser.Email)
// 				assert.Equal(t, "+1234567890", *gotUser.Phone)
// 				assert.Equal(t, "active", gotUser.Status)
// 				assert.Equal(t, 75, gotUser.ProfileCompletionPct)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_UpdateUser(t *testing.T) {
// 	user := createTestUser()
//
// 	tests := []struct {
// 		name      string
// 		user      core.User
// 		setupMock func(*MockUserQuerier, core.User)
// 		wantErr   bool
// 	}{
// 		{
// 			name: "successful user update",
// 			user: user,
// 			setupMock: func(m *MockUserQuerier, u core.User) {
// 				var email string
// 				if u.Email != nil {
// 					email = *u.Email
// 				}
//
// 				var phone pgtype.Text
// 				if u.Phone != nil {
// 					phone = pgtype.Text{String: *u.Phone, Valid: true}
// 				}
//
// 				params := sqlc.UpdateUserParams{
// 					ID:                          uuidToPgtypeUUID(u.ID),
// 					Email:                       email,
// 					Phone:                       phone,
// 					Role:                        u.Role,
// 					Status:                      pgtype.Text{String: u.Status, Valid: true},
// 					IsSmsOnly:                   pgtype.Bool{Bool: u.IsSMSOnly, Valid: true},
// 					SmsConsentGiven:             pgtype.Bool{Bool: u.SMSConsentGiven, Valid: true},
// 					PopiaConsentGiven:           pgtype.Bool{Bool: u.POPIAConsentGiven, Valid: true},
// 					ConsentDate:                 timePtrToPgtypeTimestamp(u.ConsentDate),
// 					ProfileCompletionPercentage: pgtype.Int4{Int32: int32(u.ProfileCompletionPct), Valid: true},
// 				}
// 				m.On("UpdateUser", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name: "user update with nil email and phone",
// 			user: func() core.User {
// 				u := createTestUser()
// 				u.Email = nil
// 				u.Phone = nil
// 				return u
// 			}(),
// 			setupMock: func(m *MockUserQuerier, u core.User) {
// 				params := sqlc.UpdateUserParams{
// 					ID:                          uuidToPgtypeUUID(u.ID),
// 					Email:                       "",
// 					Phone:                       pgtype.Text{Valid: false},
// 					Role:                        u.Role,
// 					Status:                      pgtype.Text{String: u.Status, Valid: true},
// 					IsSmsOnly:                   pgtype.Bool{Bool: u.IsSMSOnly, Valid: true},
// 					SmsConsentGiven:             pgtype.Bool{Bool: u.SMSConsentGiven, Valid: true},
// 					PopiaConsentGiven:           pgtype.Bool{Bool: u.POPIAConsentGiven, Valid: true},
// 					ConsentDate:                 timePtrToPgtypeTimestamp(u.ConsentDate),
// 					ProfileCompletionPercentage: pgtype.Int4{Int32: int32(u.ProfileCompletionPct), Valid: true},
// 				}
// 				m.On("UpdateUser", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name: "database error",
// 			user: user,
// 			setupMock: func(m *MockUserQuerier, u core.User) {
// 				m.On("UpdateUser", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.user)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.UpdateUser(ctx, tt.user)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_DeactivateUser(t *testing.T) {
// 	userID := uuid.New()
//
// 	tests := []struct {
// 		name      string
// 		userID    uuid.UUID
// 		setupMock func(*MockUserQuerier, uuid.UUID)
// 		wantErr   bool
// 	}{
// 		{
// 			name:   "successful deactivation",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				params := sqlc.UpdateUserStatusParams{
// 					ID:     uuidToPgtypeUUID(id),
// 					Status: pgtype.Text{String: "inactive", Valid: true},
// 				}
// 				m.On("UpdateUserStatus", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:   "database error",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				m.On("UpdateUserStatus", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.DeactivateUser(ctx, tt.userID)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_DeleteUser(t *testing.T) {
// 	userID := uuid.New()
//
// 	tests := []struct {
// 		name      string
// 		userID    uuid.UUID
// 		setupMock func(*MockUserQuerier, uuid.UUID)
// 		wantErr   bool
// 	}{
// 		{
// 			name:   "successful deletion",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				m.On("DeleteUser", mock.Anything, uuidToPgtypeUUID(id)).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:   "database error",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				m.On("DeleteUser", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.DeleteUser(ctx, tt.userID)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_ListUsers(t *testing.T) {
// 	tests := []struct {
// 		name      string
// 		role      string
// 		limit     int
// 		offset    int
// 		setupMock func(*MockUserQuerier, string, int, int)
// 		wantCount int
// 		wantErr   bool
// 	}{
// 		{
// 			name:   "successful listing",
// 			role:   "patient",
// 			limit:  10,
// 			offset: 0,
// 			setupMock: func(m *MockUserQuerier, role string, limit, offset int) {
// 				params := sqlc.ListUsersByRoleParams{
// 					Role:   role,
// 					Limit:  int32(limit),
// 					Offset: int32(offset),
// 				}
// 				rows := []sqlc.ListUsersByRoleRow{
// 					{
// 						ID:                          uuidToPgtypeUUID(uuid.New()),
// 						Email:                       "user1@example.com",
// 						Phone:                       pgtype.Text{String: "+12345678901", Valid: true},
// 						Role:                        role,
// 						Status:                      pgtype.Text{String: "active", Valid: true},
// 						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
// 						LastLogin:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 						ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
// 						CreatedAt:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 					},
// 					{
// 						ID:                          uuidToPgtypeUUID(uuid.New()),
// 						Email:                       "user2@example.com",
// 						Phone:                       pgtype.Text{String: "+12345678902", Valid: true},
// 						Role:                        role,
// 						Status:                      pgtype.Text{String: "inactive", Valid: true},
// 						IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
// 						LastLogin:                   pgtype.Timestamp{Valid: false},
// 						ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
// 						CreatedAt:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 					},
// 				}
// 				m.On("ListUsersByRole", mock.Anything, params).Return(rows, nil)
// 			},
// 			wantCount: 2,
// 			wantErr:   false,
// 		},
// 		{
// 			name:   "empty result",
// 			role:   "doctor",
// 			limit:  10,
// 			offset: 0,
// 			setupMock: func(m *MockUserQuerier, role string, limit, offset int) {
// 				params := sqlc.ListUsersByRoleParams{
// 					Role:   role,
// 					Limit:  int32(limit),
// 					Offset: int32(offset),
// 				}
// 				m.On("ListUsersByRole", mock.Anything, params).Return([]sqlc.ListUsersByRoleRow{}, nil)
// 			},
// 			wantCount: 0,
// 			wantErr:   false,
// 		},
// 		{
// 			name:   "database error",
// 			role:   "patient",
// 			limit:  10,
// 			offset: 0,
// 			setupMock: func(m *MockUserQuerier, role string, limit, offset int) {
// 				m.On("ListUsersByRole", mock.Anything, mock.Anything).
// 					Return([]sqlc.ListUsersByRoleRow{}, errors.New("database error"))
// 			},
// 			wantCount: 0,
// 			wantErr:   true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.role, tt.limit, tt.offset)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			users, err := repo.ListUsers(ctx, tt.role, tt.limit, tt.offset)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 				assert.Len(t, users, tt.wantCount)
// 				if tt.wantCount > 0 {
// 					assert.Equal(t, tt.role, users[0].Role)
// 				}
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_CountUsers(t *testing.T) {
// 	tests := []struct {
// 		name      string
// 		role      string
// 		setupMock func(*MockUserQuerier, string)
// 		wantCount int64
// 		wantErr   bool
// 	}{
// 		{
// 			name: "successful count",
// 			role: "patient",
// 			setupMock: func(m *MockUserQuerier, role string) {
// 				m.On("CountUsersByRole", mock.Anything, role).Return(int64(42), nil)
// 			},
// 			wantCount: 42,
// 			wantErr:   false,
// 		},
// 		{
// 			name: "database error",
// 			role: "patient",
// 			setupMock: func(m *MockUserQuerier, role string) {
// 				m.On("CountUsersByRole", mock.Anything, role).
// 					Return(int64(0), errors.New("database error"))
// 			},
// 			wantCount: 0,
// 			wantErr:   true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.role)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			gotCount, err := repo.CountUsers(ctx, tt.role)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 				assert.Equal(t, tt.wantCount, gotCount)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_GetUserProfile(t *testing.T) {
// 	userID := uuid.New()
//
// 	tests := []struct {
// 		name        string
// 		userID      uuid.UUID
// 		setupMock   func(*MockUserQuerier, uuid.UUID)
// 		wantUser    bool
// 		wantProfile bool
// 		wantErr     bool
// 	}{
// 		{
// 			name:   "successful profile retrieval",
// 			userID: userID,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID) {
// 				// Note: This test currently only tests user retrieval
// 				// Patient profile fetching is marked as TODO in the actual code
// 				m.On("GetUserByID", mock.Anything, uuidToPgtypeUUID(id)).
// 					Return(createTestUserRow(id, "test@example.com", "+1234567890"), nil)
// 			},
// 			wantUser:    true,
// 			wantProfile: false, // Patient profile not implemented yet
// 			wantErr:     false,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			gotUser, gotProfile, err := repo.GetUserProfile(ctx, tt.userID)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 				if tt.wantUser {
// 					assert.Equal(t, tt.userID, gotUser.ID)
// 				}
// 				if tt.wantProfile {
// 					// When patient profile is implemented, add assertions here
// 					assert.NotNil(t, gotProfile)
// 				} else {
// 					// Currently returns empty patient profile
// 					assert.Equal(t, patients.PatientProfile{}, gotProfile)
// 				}
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_UpdateUserEmail(t *testing.T) {
// 	userID := uuid.New()
// 	newEmail := "newemail@example.com"
//
// 	tests := []struct {
// 		name      string
// 		userID    uuid.UUID
// 		email     string
// 		setupMock func(*MockUserQuerier, uuid.UUID, string)
// 		wantErr   bool
// 	}{
// 		{
// 			name:   "successful email update",
// 			userID: userID,
// 			email:  newEmail,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID, email string) {
// 				params := sqlc.UpdateUserEmailParams{
// 					ID:    uuidToPgtypeUUID(id),
// 					Email: email,
// 				}
// 				m.On("UpdateUserEmail", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:   "database error",
// 			userID: userID,
// 			email:  newEmail,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID, email string) {
// 				m.On("UpdateUserEmail", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID, tt.email)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.UpdateUserEmail(ctx, tt.userID, tt.email)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_UpdateUserPhone(t *testing.T) {
// 	userID := uuid.New()
// 	newPhone := "+9876543210"
//
// 	tests := []struct {
// 		name      string
// 		userID    uuid.UUID
// 		phone     string
// 		setupMock func(*MockUserQuerier, uuid.UUID, string)
// 		wantErr   bool
// 	}{
// 		{
// 			name:   "successful phone update",
// 			userID: userID,
// 			phone:  newPhone,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID, phone string) {
// 				params := sqlc.UpdateUserPhoneParams{
// 					ID:    uuidToPgtypeUUID(id),
// 					Phone: pgtype.Text{String: phone, Valid: true},
// 				}
// 				m.On("UpdateUserPhone", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:   "database error",
// 			userID: userID,
// 			phone:  newPhone,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID, phone string) {
// 				m.On("UpdateUserPhone", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID, tt.phone)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.UpdateUserPhone(ctx, tt.userID, tt.phone)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_UpdateUserConsents(t *testing.T) {
// 	userID := uuid.New()
// 	consentDate := time.Now()
//
// 	tests := []struct {
// 		name         string
// 		userID       uuid.UUID
// 		smsConsent   bool
// 		popiaConsent bool
// 		consentDate  time.Time
// 		setupMock    func(*MockUserQuerier, uuid.UUID, bool, bool, time.Time)
// 		wantErr      bool
// 	}{
// 		{
// 			name:         "successful consent update",
// 			userID:       userID,
// 			smsConsent:   true,
// 			popiaConsent: true,
// 			consentDate:  consentDate,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID, sms, popia bool, date time.Time) {
// 				params := sqlc.UpdateUserConsentsParams{
// 					ID:                uuidToPgtypeUUID(id),
// 					SmsConsentGiven:   pgtype.Bool{Bool: sms, Valid: true},
// 					PopiaConsentGiven: pgtype.Bool{Bool: popia, Valid: true},
// 					ConsentDate:       pgtype.Timestamp{Time: date, Valid: true},
// 				}
// 				m.On("UpdateUserConsents", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:         "database error",
// 			userID:       userID,
// 			smsConsent:   false,
// 			popiaConsent: false,
// 			consentDate:  consentDate,
// 			setupMock: func(m *MockUserQuerier, id uuid.UUID, sms, popia bool, date time.Time) {
// 				m.On("UpdateUserConsents", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userID, tt.smsConsent, tt.popiaConsent, tt.consentDate)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.UpdateUserConsents(ctx, tt.userID, tt.smsConsent, tt.popiaConsent, tt.consentDate)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_BulkUpdateStatus(t *testing.T) {
// 	userIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
// 	newStatus := "suspended"
//
// 	tests := []struct {
// 		name      string
// 		userIDs   []uuid.UUID
// 		status    string
// 		setupMock func(*MockUserQuerier, []uuid.UUID, string)
// 		wantErr   bool
// 	}{
// 		{
// 			name:    "successful bulk update",
// 			userIDs: userIDs,
// 			status:  newStatus,
// 			setupMock: func(m *MockUserQuerier, ids []uuid.UUID, status string) {
// 				pgIDs := make([]pgtype.UUID, len(ids))
// 				for i, id := range ids {
// 					pgIDs[i] = uuidToPgtypeUUID(id)
// 				}
// 				params := sqlc.BulkUpdateUserStatusParams{
// 					Column1: pgIDs,
// 					Status:  pgtype.Text{String: status, Valid: true},
// 				}
// 				m.On("BulkUpdateUserStatus", mock.Anything, params).Return(nil)
// 			},
// 			wantErr: false,
// 		},
// 		{
// 			name:    "database error",
// 			userIDs: userIDs,
// 			status:  newStatus,
// 			setupMock: func(m *MockUserQuerier, ids []uuid.UUID, status string) {
// 				m.On("BulkUpdateUserStatus", mock.Anything, mock.Anything).
// 					Return(errors.New("database error"))
// 			},
// 			wantErr: true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userIDs, tt.status)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			err := repo.BulkUpdateStatus(ctx, tt.userIDs, tt.status)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
//
// func TestUserRepository_GetUsersByIDs(t *testing.T) {
// 	userIDs := []uuid.UUID{uuid.New(), uuid.New()}
//
// 	tests := []struct {
// 		name      string
// 		userIDs   []uuid.UUID
// 		setupMock func(*MockUserQuerier, []uuid.UUID)
// 		wantCount int
// 		wantErr   bool
// 	}{
// 		{
// 			name:    "successful retrieval by IDs",
// 			userIDs: userIDs,
// 			setupMock: func(m *MockUserQuerier, ids []uuid.UUID) {
// 				pgIDs := make([]pgtype.UUID, len(ids))
// 				for i, id := range ids {
// 					pgIDs[i] = uuidToPgtypeUUID(id)
// 				}
// 				rows := []sqlc.GetUsersByIDsRow{
// 					{
// 						ID:                          uuidToPgtypeUUID(ids[0]),
// 						Email:                       "user1@example.com",
// 						Phone:                       pgtype.Text{String: "+12345678901", Valid: true},
// 						Role:                        "patient",
// 						Status:                      pgtype.Text{String: "active", Valid: true},
// 						IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
// 						LastLogin:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 						LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
// 						IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
// 						ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
// 						CreatedAt:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 						UpdatedAt:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 					},
// 					{
// 						ID:                          uuidToPgtypeUUID(ids[1]),
// 						Email:                       "user2@example.com",
// 						Phone:                       pgtype.Text{String: "+12345678902", Valid: true},
// 						Role:                        "doctor",
// 						Status:                      pgtype.Text{String: "inactive", Valid: true},
// 						IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
// 						LastLogin:                   pgtype.Timestamp{Valid: false},
// 						LoginCount:                  pgtype.Int4{Int32: 0, Valid: true},
// 						IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
// 						ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
// 						CreatedAt:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 						UpdatedAt:                   pgtype.Timestamp{Time: time.Now(), Valid: true},
// 					},
// 				}
// 				m.On("GetUsersByIDs", mock.Anything, pgIDs).Return(rows, nil)
// 			},
// 			wantCount: 2,
// 			wantErr:   false,
// 		},
// 		{
// 			name:    "database error",
// 			userIDs: userIDs,
// 			setupMock: func(m *MockUserQuerier, ids []uuid.UUID) {
// 				m.On("GetUsersByIDs", mock.Anything, mock.Anything).
// 					Return([]sqlc.GetUsersByIDsRow{}, errors.New("database error"))
// 			},
// 			wantCount: 0,
// 			wantErr:   true,
// 		},
// 	}
//
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			mockQuerier := new(MockUserQuerier)
// 			tt.setupMock(mockQuerier, tt.userIDs)
//
// 			repo := &userRepository{querier: mockQuerier}
// 			ctx := context.Background()
//
// 			users, err := repo.GetUsersByIDs(ctx, tt.userIDs)
//
// 			if tt.wantErr {
// 				require.Error(t, err)
// 			} else {
// 				require.NoError(t, err)
// 				assert.Len(t, users, tt.wantCount)
// 				if tt.wantCount > 0 {
// 					assert.Equal(t, tt.userIDs[0], users[0].ID)
// 					assert.Equal(t, tt.userIDs[1], users[1].ID)
// 				}
// 			}
//
// 			mockQuerier.AssertExpectations(t)
// 		})
// 	}
// }
