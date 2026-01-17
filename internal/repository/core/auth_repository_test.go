package core

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks" // Import generated mocks
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuthRepository_CreateUser(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name          string
		user          core.User
		passwordHash  string
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedError error
	}{
		{
			name: "successful creation with email",
			user: core.User{
				Email:             stringPtr("test@example.com"),
				Role:              "patient",
				Status:            "pending",
				IsSMSOnly:         false,
				SMSConsentGiven:   true,
				POPIAConsentGiven: true,
				ConsentDate:       &now,
			},
			passwordHash: "$2a$10$hashedpassword",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.CreateUserRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"), Valid: true},
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "pending", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
					LastLogin:                   pgtype.Timestamp{Valid: false},
					LoginCount:                  pgtype.Int4{Int32: 0, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreateUser", ctx, mock.MatchedBy(func(p sqlc.CreateUserParams) bool {
					return p.Email == "test@example.com" &&
						p.PasswordHash.String == "$2a$10$hashedpassword" &&
						p.Role == "patient" &&
						p.Status.String == "pending" &&
						p.IsSmsOnly.Bool == false &&
						p.SmsConsentGiven.Bool == true &&
						p.PopiaConsentGiven.Bool == true &&
						p.ConsentDate.Time.Equal(now)
				})).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                stringPtr("test@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "pending",
				IsVerified:           false,
				LastLogin:            nil,
				LoginCount:           0,
				IsSMSOnly:            false,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    false,
				ProfileCompletionPct: 0,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedError: nil,
		},
		{
			name: "successful creation with phone",
			user: core.User{
				Phone:             stringPtr("+1234567890"),
				Role:              "patient",
				Status:            "pending",
				IsSMSOnly:         true,
				SMSConsentGiven:   true,
				POPIAConsentGiven: true,
				ConsentDate:       &now,
			},
			passwordHash: "$2a$10$hashedpassword",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.CreateUserRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"), Valid: true},
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "pending", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
					LastLogin:                   pgtype.Timestamp{Valid: false},
					LoginCount:                  pgtype.Int4{Int32: 0, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreateUser", ctx, mock.MatchedBy(func(p sqlc.CreateUserParams) bool {
					return p.Phone.String == "+1234567890" &&
						p.PasswordHash.String == "$2a$10$hashedpassword" &&
						p.Role == "patient" &&
						p.Status.String == "pending" &&
						p.IsSmsOnly.Bool == true &&
						p.SmsConsentGiven.Bool == true &&
						p.PopiaConsentGiven.Bool == true &&
						p.ConsentDate.Time.Equal(now)
				})).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
				Email:                nil,
				Phone:                stringPtr("+1234567890"),
				Role:                 "patient",
				Status:               "pending",
				IsVerified:           false,
				LastLogin:            nil,
				LoginCount:           0,
				IsSMSOnly:            true,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    false,
				ProfileCompletionPct: 0,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedError: nil,
		},
		{
			name: "duplicate email error",
			user: core.User{
				Email: stringPtr("duplicate@example.com"),
				Role:  "patient",
			},
			passwordHash: "$2a$10$hashed",
			mockSetup: func(m *mocks.Querier) {
				m.On("CreateUser", ctx, mock.Anything).Return(sqlc.CreateUserRow{}, &pgconn.PgError{
					Code:           "23505",
					ConstraintName: "users_email_key",
				})
			},
			expectedUser:  core.User{},
			expectedError: domain.ErrDuplicateEmail,
		},
		{
			name: "duplicate phone error",
			user: core.User{
				Phone: stringPtr("+1234567890"),
				Role:  "patient",
			},
			passwordHash: "$2a$10$hashed",
			mockSetup: func(m *mocks.Querier) {
				m.On("CreateUser", ctx, mock.Anything).Return(sqlc.CreateUserRow{}, &pgconn.PgError{
					Code:           "23505",
					ConstraintName: "users_phone_key",
				})
			},
			expectedUser:  core.User{},
			expectedError: domain.ErrDuplicatePhone,
		},
		{
			name: "generic database error",
			user: core.User{
				Email: stringPtr("error@example.com"),
				Role:  "patient",
			},
			passwordHash: "$2a$10$hashed",
			mockSetup: func(m *mocks.Querier) {
				m.On("CreateUser", ctx, mock.Anything).Return(sqlc.CreateUserRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			gotUser, err := repo.CreateUser(ctx, tt.user, tt.passwordHash)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "create user failed")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Equal(t, tt.expectedUser, gotUser)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, gotUser.ID)
				assert.Equal(t, tt.expectedUser.Email, gotUser.Email)
				assert.Equal(t, tt.expectedUser.Phone, gotUser.Phone)
				assert.Equal(t, tt.expectedUser.Role, gotUser.Role)
				assert.Equal(t, tt.expectedUser.Status, gotUser.Status)
				assert.Equal(t, tt.expectedUser.IsVerified, gotUser.IsVerified)
				assert.Equal(t, tt.expectedUser.LastLogin, gotUser.LastLogin)
				assert.Equal(t, tt.expectedUser.LoginCount, gotUser.LoginCount)
				assert.Equal(t, tt.expectedUser.IsSMSOnly, gotUser.IsSMSOnly)
				assert.Equal(t, tt.expectedUser.SMSConsentGiven, gotUser.SMSConsentGiven)
				assert.Equal(t, tt.expectedUser.POPIAConsentGiven, gotUser.POPIAConsentGiven)
				assert.Equal(t, tt.expectedUser.ProfileCompletionPct, gotUser.ProfileCompletionPct)
				assert.Equal(t, tt.expectedUser.CreatedAt, gotUser.CreatedAt)
				assert.Equal(t, tt.expectedUser.UpdatedAt, gotUser.UpdatedAt)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByVerificationToken(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	expires := now.Add(time.Hour * 24)

	tests := []struct {
		name          string
		token         string
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedHash  string
		expectedError error
	}{
		{
			name:  "successful retrieval",
			token: "verification-token",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByVerificationTokenRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"), Valid: true},
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "pending", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
					VerificationToken:           pgtype.Text{String: "verification-token", Valid: true},
					VerificationExpires:         pgtype.Timestamp{Time: expires, Valid: true},
					LastLogin:                   pgtype.Timestamp{Valid: false},
					LoginCount:                  pgtype.Int4{Int32: 0, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetUserByVerificationToken", ctx, pgtype.Text{String: "verification-token", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                stringPtr("test@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "pending",
				IsVerified:           false,
				VerificationToken:    stringPtr("verification-token"),
				VerificationExpires:  &expires,
				LastLogin:            nil,
				LoginCount:           0,
				IsSMSOnly:            false,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 0,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user not found",
			token: "invalid-token",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByVerificationToken", ctx, pgtype.Text{String: "invalid-token", Valid: true}).Return(sqlc.GetUserByVerificationTokenRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			token: "error-token",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByVerificationToken", ctx, pgtype.Text{String: "error-token", Valid: true}).Return(sqlc.GetUserByVerificationTokenRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			gotUser, gotHash, err := repo.GetUserByVerificationToken(ctx, tt.token)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get user by verification token failed")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Equal(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, gotUser.ID)
				assert.Equal(t, tt.expectedUser.Email, gotUser.Email)
				assert.Equal(t, tt.expectedUser.Phone, gotUser.Phone)
				assert.Equal(t, tt.expectedUser.Role, gotUser.Role)
				assert.Equal(t, tt.expectedUser.Status, gotUser.Status)
				assert.Equal(t, tt.expectedUser.IsVerified, gotUser.IsVerified)
				assert.Equal(t, tt.expectedUser.VerificationToken, gotUser.VerificationToken)
				assert.Equal(t, tt.expectedUser.VerificationExpires, gotUser.VerificationExpires)
				assert.Equal(t, tt.expectedUser.LastLogin, gotUser.LastLogin)
				assert.Equal(t, tt.expectedUser.LoginCount, gotUser.LoginCount)
				assert.Equal(t, tt.expectedUser.IsSMSOnly, gotUser.IsSMSOnly)
				assert.Equal(t, tt.expectedUser.SMSConsentGiven, gotUser.SMSConsentGiven)
				assert.Equal(t, tt.expectedUser.POPIAConsentGiven, gotUser.POPIAConsentGiven)
				assert.Equal(t, tt.expectedUser.ProfileCompletionPct, gotUser.ProfileCompletionPct)
				assert.Equal(t, tt.expectedUser.CreatedAt, gotUser.CreatedAt)
				assert.Equal(t, tt.expectedUser.UpdatedAt, gotUser.UpdatedAt)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByPasswordResetToken(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	expires := now.Add(time.Hour * 1)

	tests := []struct {
		name          string
		token         string
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedHash  string
		expectedError error
	}{
		{
			name:  "successful retrieval",
			token: "reset-token",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByPasswordResetTokenRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"), Valid: true},
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					ResetPasswordToken:          pgtype.Text{String: "reset-token", Valid: true},
					ResetPasswordExpires:        pgtype.Timestamp{Time: expires, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now, Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 1, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetUserByPasswordResetToken", ctx, pgtype.Text{String: "reset-token", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                stringPtr("test@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				ResetPasswordToken:   stringPtr("reset-token"),
				ResetPasswordExpires: &expires,
				LastLogin:            &now,
				LoginCount:           1,
				IsSMSOnly:            false,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 50,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user not found",
			token: "invalid-token",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPasswordResetToken", ctx, pgtype.Text{String: "invalid-token", Valid: true}).Return(sqlc.GetUserByPasswordResetTokenRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			token: "error-token",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPasswordResetToken", ctx, pgtype.Text{String: "error-token", Valid: true}).Return(sqlc.GetUserByPasswordResetTokenRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			gotUser, gotHash, err := repo.GetUserByPasswordResetToken(ctx, tt.token)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get user by password reset token failed")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Equal(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, gotUser.ID)
				assert.Equal(t, tt.expectedUser.Email, gotUser.Email)
				assert.Equal(t, tt.expectedUser.Phone, gotUser.Phone)
				assert.Equal(t, tt.expectedUser.Role, gotUser.Role)
				assert.Equal(t, tt.expectedUser.Status, gotUser.Status)
				assert.Equal(t, tt.expectedUser.IsVerified, gotUser.IsVerified)
				assert.Equal(t, tt.expectedUser.ResetPasswordToken, gotUser.ResetPasswordToken)
				assert.Equal(t, tt.expectedUser.ResetPasswordExpires, gotUser.ResetPasswordExpires)
				assert.Equal(t, tt.expectedUser.LastLogin, gotUser.LastLogin)
				assert.Equal(t, tt.expectedUser.LoginCount, gotUser.LoginCount)
				assert.Equal(t, tt.expectedUser.IsSMSOnly, gotUser.IsSMSOnly)
				assert.Equal(t, tt.expectedUser.SMSConsentGiven, gotUser.SMSConsentGiven)
				assert.Equal(t, tt.expectedUser.POPIAConsentGiven, gotUser.POPIAConsentGiven)
				assert.Equal(t, tt.expectedUser.ProfileCompletionPct, gotUser.ProfileCompletionPct)
				assert.Equal(t, tt.expectedUser.CreatedAt, gotUser.CreatedAt)
				assert.Equal(t, tt.expectedUser.UpdatedAt, gotUser.UpdatedAt)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByEmail(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name          string
		email         string
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedHash  string
		expectedError error
	}{
		{
			name:  "successful retrieval",
			email: "test@example.com",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByEmailRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"), Valid: true},
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					VerificationToken:           pgtype.Text{Valid: false},
					VerificationExpires:         pgtype.Timestamp{Valid: false},
					LastLogin:                   pgtype.Timestamp{Time: now, Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 1, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetUserByEmail", ctx, "test@example.com").Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                stringPtr("test@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				VerificationToken:    nil,
				VerificationExpires:  nil,
				LastLogin:            &now,
				LoginCount:           1,
				IsSMSOnly:            false,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 50,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user not found",
			email: "missing@example.com",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByEmail", ctx, "missing@example.com").Return(sqlc.GetUserByEmailRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			email: "error@example.com",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByEmail", ctx, "error@example.com").Return(sqlc.GetUserByEmailRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			gotUser, gotHash, err := repo.GetUserByEmail(ctx, tt.email)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get user by email failed")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Equal(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, gotUser.ID)
				assert.Equal(t, tt.expectedUser.Email, gotUser.Email)
				assert.Equal(t, tt.expectedUser.Phone, gotUser.Phone)
				assert.Equal(t, tt.expectedUser.Role, gotUser.Role)
				assert.Equal(t, tt.expectedUser.Status, gotUser.Status)
				assert.Equal(t, tt.expectedUser.IsVerified, gotUser.IsVerified)
				assert.Equal(t, tt.expectedUser.VerificationToken, gotUser.VerificationToken)
				assert.Equal(t, tt.expectedUser.VerificationExpires, gotUser.VerificationExpires)
				assert.Equal(t, tt.expectedUser.LastLogin, gotUser.LastLogin)
				assert.Equal(t, tt.expectedUser.LoginCount, gotUser.LoginCount)
				assert.Equal(t, tt.expectedUser.IsSMSOnly, gotUser.IsSMSOnly)
				assert.Equal(t, tt.expectedUser.SMSConsentGiven, gotUser.SMSConsentGiven)
				assert.Equal(t, tt.expectedUser.POPIAConsentGiven, gotUser.POPIAConsentGiven)
				assert.Equal(t, tt.expectedUser.ProfileCompletionPct, gotUser.ProfileCompletionPct)
				assert.Equal(t, tt.expectedUser.CreatedAt, gotUser.CreatedAt)
				assert.Equal(t, tt.expectedUser.UpdatedAt, gotUser.UpdatedAt)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByPhone(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name          string
		phone         string
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedError error
	}{
		{
			name:  "successful retrieval",
			phone: "+1234567890",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByPhoneRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"), Valid: true},
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now, Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 1, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "+1234567890", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                nil,
				Phone:                stringPtr("+1234567890"),
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            &now,
				LoginCount:           1,
				IsSMSOnly:            true,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 50,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedError: nil,
		},
		{
			name:  "user not found",
			phone: "+9999999999",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "+9999999999", Valid: true}).Return(sqlc.GetUserByPhoneRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			phone: "+errorphone",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "+errorphone", Valid: true}).Return(sqlc.GetUserByPhoneRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			gotUser, err := repo.GetUserByPhone(ctx, tt.phone)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get user by phone failed")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Equal(t, tt.expectedUser, gotUser)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, gotUser.ID)
				assert.Equal(t, tt.expectedUser.Email, gotUser.Email)
				assert.Equal(t, tt.expectedUser.Phone, gotUser.Phone)
				assert.Equal(t, tt.expectedUser.Role, gotUser.Role)
				assert.Equal(t, tt.expectedUser.Status, gotUser.Status)
				assert.Equal(t, tt.expectedUser.IsVerified, gotUser.IsVerified)
				assert.Equal(t, tt.expectedUser.LastLogin, gotUser.LastLogin)
				assert.Equal(t, tt.expectedUser.LoginCount, gotUser.LoginCount)
				assert.Equal(t, tt.expectedUser.IsSMSOnly, gotUser.IsSMSOnly)
				assert.Equal(t, tt.expectedUser.SMSConsentGiven, gotUser.SMSConsentGiven)
				assert.Equal(t, tt.expectedUser.POPIAConsentGiven, gotUser.POPIAConsentGiven)
				assert.Equal(t, tt.expectedUser.ProfileCompletionPct, gotUser.ProfileCompletionPct)
				assert.Equal(t, tt.expectedUser.CreatedAt, gotUser.CreatedAt)
				assert.Equal(t, tt.expectedUser.UpdatedAt, gotUser.UpdatedAt)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByPhoneWithHash(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name          string
		phone         string
		mockSetup     func(*mocks.Querier)
		expectedUser  core.User
		expectedHash  string
		expectedError error
	}{
		{
			name:  "successful retrieval",
			phone: "+1234567890",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByPhoneWithHashRow{
					ID:                          pgtype.UUID{Bytes: uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"), Valid: true},
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now, Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 1, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetUserByPhoneWithHash", ctx, pgtype.Text{String: "+1234567890", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                nil,
				Phone:                stringPtr("+1234567890"),
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            &now,
				LoginCount:           1,
				IsSMSOnly:            true,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 50,
				CreatedAt:            now,
				UpdatedAt:            now,
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user not found",
			phone: "+9999999999",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhoneWithHash", ctx, pgtype.Text{String: "+9999999999", Valid: true}).Return(sqlc.GetUserByPhoneWithHashRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			phone: "+errorphone",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhoneWithHash", ctx, pgtype.Text{String: "+errorphone", Valid: true}).Return(sqlc.GetUserByPhoneWithHashRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			gotUser, gotHash, err := repo.GetUserByPhoneWithHash(ctx, tt.phone)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get user by phone with hash failed")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Equal(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser.ID, gotUser.ID)
				assert.Equal(t, tt.expectedUser.Email, gotUser.Email)
				assert.Equal(t, tt.expectedUser.Phone, gotUser.Phone)
				assert.Equal(t, tt.expectedUser.Role, gotUser.Role)
				assert.Equal(t, tt.expectedUser.Status, gotUser.Status)
				assert.Equal(t, tt.expectedUser.IsVerified, gotUser.IsVerified)
				assert.Equal(t, tt.expectedUser.LastLogin, gotUser.LastLogin)
				assert.Equal(t, tt.expectedUser.LoginCount, gotUser.LoginCount)
				assert.Equal(t, tt.expectedUser.IsSMSOnly, gotUser.IsSMSOnly)
				assert.Equal(t, tt.expectedUser.SMSConsentGiven, gotUser.SMSConsentGiven)
				assert.Equal(t, tt.expectedUser.POPIAConsentGiven, gotUser.POPIAConsentGiven)
				assert.Equal(t, tt.expectedUser.ProfileCompletionPct, gotUser.ProfileCompletionPct)
				assert.Equal(t, tt.expectedUser.CreatedAt, gotUser.CreatedAt)
				assert.Equal(t, tt.expectedUser.UpdatedAt, gotUser.UpdatedAt)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_VerifyUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful verification",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("VerifyUser", ctx, pgtype.UUID{Bytes: userID, Valid: true}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "generic database error",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("VerifyUser", ctx, pgtype.UUID{Bytes: userID, Valid: true}).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			err := repo.VerifyUser(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "verify user failed")
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

func TestAuthRepository_SetVerificationToken(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	token := "verification-token"
	expires := time.Now().Add(time.Hour * 24)

	tests := []struct {
		name          string
		id            uuid.UUID
		token         string
		expires       time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful set",
			id:      userID,
			token:   token,
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetVerificationToken", ctx, mock.MatchedBy(func(p sqlc.SetVerificationTokenParams) bool {
					return p.ID.Bytes == userID &&
						p.VerificationToken.String == token &&
						p.VerificationExpires.Time.Equal(expires)
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "generic database error",
			id:      userID,
			token:   token,
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetVerificationToken", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			err := repo.SetVerificationToken(ctx, tt.id, tt.token, tt.expires)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "set verification token failed")
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

func TestAuthRepository_SetPasswordResetToken(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	token := "reset-token"
	expires := time.Now().Add(time.Hour * 1)

	tests := []struct {
		name          string
		id            uuid.UUID
		token         string
		expires       time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful set",
			id:      userID,
			token:   token,
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetPasswordResetToken", ctx, mock.MatchedBy(func(p sqlc.SetPasswordResetTokenParams) bool {
					return p.ID.Bytes == userID &&
						p.ResetPasswordToken.String == token &&
						p.ResetPasswordExpires.Time.Equal(expires)
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "generic database error",
			id:      userID,
			token:   token,
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetPasswordResetToken", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			err := repo.SetPasswordResetToken(ctx, tt.id, tt.token, tt.expires)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "set password reset token failed")
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

func TestAuthRepository_UpdateUserPassword(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	passwordHash := "$2a$10$newhashedpassword"

	tests := []struct {
		name          string
		id            uuid.UUID
		passwordHash  string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:         "successful update",
			id:           userID,
			passwordHash: passwordHash,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPassword", ctx, mock.MatchedBy(func(p sqlc.UpdateUserPasswordParams) bool {
					return p.ID.Bytes == userID &&
						p.PasswordHash.String == passwordHash
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "generic database error",
			id:           userID,
			passwordHash: passwordHash,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPassword", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			err := repo.UpdateUserPassword(ctx, tt.id, tt.passwordHash)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "update user password failed")
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

// Helper function
func stringPtr(s string) *string { return &s }
