package core

import (
	"context"
	"fmt"
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
	now := nowTime()

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
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
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
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
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
			name: "successful creation with both email and phone",
			user: core.User{
				Email:             stringPtr("both@example.com"),
				Phone:             stringPtr("+1234567892"),
				Role:              "doctor",
				Status:            "pending",
				IsSMSOnly:         false,
				SMSConsentGiven:   false,
				POPIAConsentGiven: false,
				ConsentDate:       &now,
			},
			passwordHash: "$2a$10$hashedpassword",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.CreateUserRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174002"),
					Email:                       "both@example.com",
					Phone:                       pgtype.Text{String: "+1234567892", Valid: true},
					Role:                        "doctor",
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
					return p.Email == "both@example.com" &&
						p.Phone.String == "+1234567892" &&
						p.PasswordHash.String == "$2a$10$hashedpassword" &&
						p.Role == "doctor" &&
						p.Status.String == "pending" &&
						p.IsSmsOnly.Bool == false &&
						p.SmsConsentGiven.Bool == false &&
						p.PopiaConsentGiven.Bool == false &&
						p.ConsentDate.Time.Equal(now)
				})).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
				Email:                stringPtr("both@example.com"),
				Phone:                stringPtr("+1234567892"),
				Role:                 "doctor",
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
			name: "creation without email or phone",
			user: core.User{
				Role:              "patient",
				Status:            "pending",
				IsSMSOnly:         false,
				SMSConsentGiven:   true,
				POPIAConsentGiven: true,
				ConsentDate:       &now,
			},
			passwordHash: "$2a$10$hashedpassword",
			mockSetup: func(m *mocks.Querier) {
				m.On("CreateUser", ctx, mock.Anything).Return(sqlc.CreateUserRow{}, &pgconn.PgError{Code: "23502"}) // not_null_violation simulation
			},
			expectedUser:  core.User{},
			expectedError: fmt.Errorf("create user failed: %w", &pgconn.PgError{Code: "23502"}),
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
				assertUserEqual(t, tt.expectedUser, gotUser)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByVerificationToken(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
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
			name:  "successful retrieval with email",
			token: "verification-token",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByVerificationTokenRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
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
			name:  "successful retrieval with phone",
			token: "verification-token-phone",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByVerificationTokenRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003"),
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567893", Valid: true},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "pending", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
					VerificationToken:           pgtype.Text{String: "verification-token-phone", Valid: true},
					VerificationExpires:         pgtype.Timestamp{Time: expires, Valid: true},
					LastLogin:                   pgtype.Timestamp{Valid: false},
					LoginCount:                  pgtype.Int4{Int32: 0, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: false, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: false, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetUserByVerificationToken", ctx, pgtype.Text{String: "verification-token-phone", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
				Email:                nil,
				Phone:                stringPtr("+1234567893"),
				Role:                 "patient",
				Status:               "pending",
				IsVerified:           false,
				VerificationToken:    stringPtr("verification-token-phone"),
				VerificationExpires:  &expires,
				LastLogin:            nil,
				LoginCount:           0,
				IsSMSOnly:            true,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    false,
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
			name:  "empty token",
			token: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByVerificationToken", ctx, pgtype.Text{String: "", Valid: true}).Return(sqlc.GetUserByVerificationTokenRow{}, pgx.ErrNoRows)
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
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByPasswordResetToken(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
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
			name:  "successful retrieval with email",
			token: "reset-token",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByPasswordResetTokenRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					ResetPasswordToken:          pgtype.Text{String: "reset-token", Valid: true},
					ResetPasswordExpires:        pgtype.Timestamp{Time: expires, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 75, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
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
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           5,
				IsSMSOnly:            false,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 75,
				CreatedAt:            now.Add(-time.Hour * 24 * 7),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user not found",
			token: "invalid-reset-token",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPasswordResetToken", ctx, pgtype.Text{String: "invalid-reset-token", Valid: true}).Return(sqlc.GetUserByPasswordResetTokenRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			token: "error-reset-token",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPasswordResetToken", ctx, pgtype.Text{String: "error-reset-token", Valid: true}).Return(sqlc.GetUserByPasswordResetTokenRow{}, assert.AnError)
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
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByEmail(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	expires := now.Add(time.Hour * 24)

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
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{Valid: false},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					VerificationToken:           pgtype.Text{Valid: false},
					VerificationExpires:         pgtype.Timestamp{Valid: false},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 10, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 90, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 30), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
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
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           10,
				IsSMSOnly:            false,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 90,
				CreatedAt:            now.Add(-time.Hour * 24 * 30),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user with verification token",
			email: "unverified@example.com",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByEmailRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
					Email:                       "unverified@example.com",
					Phone:                       pgtype.Text{Valid: false},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "pending", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: false, Valid: true},
					VerificationToken:           pgtype.Text{String: "token-123", Valid: true},
					VerificationExpires:         pgtype.Timestamp{Time: expires, Valid: true},
					LastLogin:                   pgtype.Timestamp{Valid: false},
					LoginCount:                  pgtype.Int4{Int32: 0, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: false, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: false, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 0, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
				}
				m.On("GetUserByEmail", ctx, "unverified@example.com").Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
				Email:                stringPtr("unverified@example.com"),
				Phone:                nil,
				Role:                 "patient",
				Status:               "pending",
				IsVerified:           false,
				VerificationToken:    stringPtr("token-123"),
				VerificationExpires:  &expires,
				LastLogin:            nil,
				LoginCount:           0,
				IsSMSOnly:            false,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    false,
				ProfileCompletionPct: 0,
				CreatedAt:            now.Add(-time.Hour),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedHash:  "$2a$10$hashedpassword",
			expectedError: nil,
		},
		{
			name:  "user not found",
			email: "nonexistent@example.com",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByEmail", ctx, "nonexistent@example.com").Return(sqlc.GetUserByEmailRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedHash:  "",
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "empty email",
			email: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByEmail", ctx, "").Return(sqlc.GetUserByEmailRow{}, pgx.ErrNoRows)
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
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByPhone(t *testing.T) {
	ctx := context.Background()
	now := nowTime()

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
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					Role:                        "doctor",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 15, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 100, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 60), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Minute * 30), Valid: true},
				}
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "+1234567890", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				Email:                nil,
				Phone:                stringPtr("+1234567890"),
				Role:                 "doctor",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           15,
				IsSMSOnly:            true,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 100,
				CreatedAt:            now.Add(-time.Hour * 24 * 60),
				UpdatedAt:            now.Add(-time.Minute * 30),
			},
			expectedError: nil,
		},
		{
			name:  "user with email and phone",
			phone: "+1234567891",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByPhoneRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
					Email:                       "user@example.com",
					Phone:                       pgtype.Text{String: "+1234567891", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 2), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 8, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: false, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 50, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 14), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
				}
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "+1234567891", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
				Email:                stringPtr("user@example.com"),
				Phone:                stringPtr("+1234567891"),
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            timePtr(now.Add(-time.Hour * 2)),
				LoginCount:           8,
				IsSMSOnly:            false,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 50,
				CreatedAt:            now.Add(-time.Hour * 24 * 14),
				UpdatedAt:            now.Add(-time.Hour),
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
			name:  "empty phone",
			phone: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "", Valid: true}).Return(sqlc.GetUserByPhoneRow{}, pgx.ErrNoRows)
			},
			expectedUser:  core.User{},
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:  "generic database error",
			phone: "+1234567899",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhone", ctx, pgtype.Text{String: "+1234567899", Valid: true}).Return(sqlc.GetUserByPhoneRow{}, assert.AnError)
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
				assertUserEqual(t, tt.expectedUser, gotUser)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_GetUserByPhoneWithHash(t *testing.T) {
	ctx := context.Background()
	now := nowTime()

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
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Email:                       "",
					Phone:                       pgtype.Text{String: "+1234567890", Valid: true},
					PasswordHash:                pgtype.Text{String: "$2a$10$hashedpassword", Valid: true},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 5, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: true, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: true, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 80, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 7), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
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
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           5,
				IsSMSOnly:            true,
				SMSConsentGiven:      true,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 80,
				CreatedAt:            now.Add(-time.Hour * 24 * 7),
				UpdatedAt:            now.Add(-time.Hour),
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
			name:  "user found but no password hash",
			phone: "+1234567891",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetUserByPhoneWithHashRow{
					ID:                          uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
					Email:                       "test@example.com",
					Phone:                       pgtype.Text{String: "+1234567891", Valid: true},
					PasswordHash:                pgtype.Text{Valid: false},
					Role:                        "patient",
					Status:                      pgtype.Text{String: "active", Valid: true},
					IsVerified:                  pgtype.Bool{Bool: true, Valid: true},
					LastLogin:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
					LoginCount:                  pgtype.Int4{Int32: 3, Valid: true},
					IsSmsOnly:                   pgtype.Bool{Bool: false, Valid: true},
					SmsConsentGiven:             pgtype.Bool{Bool: false, Valid: true},
					PopiaConsentGiven:           pgtype.Bool{Bool: true, Valid: true},
					ProfileCompletionPercentage: pgtype.Int4{Int32: 60, Valid: true},
					CreatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour * 24 * 3), Valid: true},
					UpdatedAt:                   pgtype.Timestamp{Time: now.Add(-time.Hour), Valid: true},
				}
				m.On("GetUserByPhoneWithHash", ctx, pgtype.Text{String: "+1234567891", Valid: true}).Return(expectedRow, nil)
			},
			expectedUser: core.User{
				ID:                   uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
				Email:                stringPtr("test@example.com"),
				Phone:                stringPtr("+1234567891"),
				Role:                 "patient",
				Status:               "active",
				IsVerified:           true,
				LastLogin:            timePtr(now.Add(-time.Hour)),
				LoginCount:           3,
				IsSMSOnly:            false,
				SMSConsentGiven:      false,
				POPIAConsentGiven:    true,
				ProfileCompletionPct: 60,
				CreatedAt:            now.Add(-time.Hour * 24 * 3),
				UpdatedAt:            now.Add(-time.Hour),
			},
			expectedHash:  "",
			expectedError: nil,
		},
		{
			name:  "generic database error",
			phone: "+1234567899",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserByPhoneWithHash", ctx, pgtype.Text{String: "+1234567899", Valid: true}).Return(sqlc.GetUserByPhoneWithHashRow{}, assert.AnError)
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
				assertUserEqual(t, tt.expectedUser, gotUser)
				assert.Equal(t, tt.expectedHash, gotHash)
			} else {
				require.NoError(t, err)
				assertUserEqual(t, tt.expectedUser, gotUser)
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
				m.On("VerifyUser", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "user not found",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("VerifyUser", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(pgx.ErrNoRows)
			},
			expectedError: fmt.Errorf("verify user failed: %w", pgx.ErrNoRows),
		},
		{
			name: "generic database error",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("VerifyUser", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(assert.AnError)
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
					assert.Equal(t, tt.expectedError.Error(), err.Error())
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
	token := "verification-token-123"
	expires := nowTime().Add(time.Hour * 24)

	tests := []struct {
		name          string
		id            uuid.UUID
		token         string
		expires       time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful set verification token",
			id:      userID,
			token:   token,
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetVerificationToken", ctx, sqlc.SetVerificationTokenParams{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					VerificationToken:   pgtype.Text{String: token, Valid: true},
					VerificationExpires: pgtype.Timestamp{Time: expires, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "empty token",
			id:      userID,
			token:   "",
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetVerificationToken", ctx, sqlc.SetVerificationTokenParams{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					VerificationToken:   pgtype.Text{String: "", Valid: true},
					VerificationExpires: pgtype.Timestamp{Time: expires, Valid: true},
				}).Return(nil)
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
					assert.Equal(t, tt.expectedError.Error(), err.Error())
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
	token := "reset-token-456"
	expires := nowTime().Add(time.Hour * 1)

	tests := []struct {
		name          string
		id            uuid.UUID
		token         string
		expires       time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful set password reset token",
			id:      userID,
			token:   token,
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetPasswordResetToken", ctx, sqlc.SetPasswordResetTokenParams{
					ID:                   uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ResetPasswordToken:   pgtype.Text{String: token, Valid: true},
					ResetPasswordExpires: pgtype.Timestamp{Time: expires, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "empty token",
			id:      userID,
			token:   "",
			expires: expires,
			mockSetup: func(m *mocks.Querier) {
				m.On("SetPasswordResetToken", ctx, sqlc.SetPasswordResetTokenParams{
					ID:                   uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ResetPasswordToken:   pgtype.Text{String: "", Valid: true},
					ResetPasswordExpires: pgtype.Timestamp{Time: expires, Valid: true},
				}).Return(nil)
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
					assert.Equal(t, tt.expectedError.Error(), err.Error())
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
			name:         "successful password update",
			id:           userID,
			passwordHash: passwordHash,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPassword", ctx, sqlc.UpdateUserPasswordParams{
					ID:           uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "empty password hash",
			id:           userID,
			passwordHash: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPassword", ctx, sqlc.UpdateUserPasswordParams{
					ID:           uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					PasswordHash: pgtype.Text{String: "", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:         "user not found",
			id:           userID,
			passwordHash: passwordHash,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserPassword", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectedError: fmt.Errorf("update user password failed: %w", pgx.ErrNoRows),
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
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_UpdateLastLogin(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful last login update",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserLastLogin", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "user not found",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserLastLogin", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(pgx.ErrNoRows)
			},
			expectedError: fmt.Errorf("update last login failed: %w", pgx.ErrNoRows),
		},
		{
			name: "generic database error",
			id:   userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateUserLastLogin", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &authRepository{querier: mockQuerier}

			err := repo.UpdateLastLogin(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "update last login failed")
				} else {
					assert.Equal(t, tt.expectedError.Error(), err.Error())
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuthRepository_handleError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name: "duplicate email error",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "users_email_key",
			},
			expected: domain.ErrDuplicateEmail,
		},
		{
			name: "duplicate phone error",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "users_phone_key",
			},
			expected: domain.ErrDuplicatePhone,
		},
		{
			name: "other unique violation",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "some_other_constraint",
			},
			expected: fmt.Errorf("duplicate constraint violation: %w", &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "some_other_constraint",
			}),
		},
		{
			name: "foreign key violation",
			err: &pgconn.PgError{
				Code: "23503",
			},
			expected: fmt.Errorf("foreign key violation: %w", &pgconn.PgError{
				Code: "23503",
			}),
		},
		{
			name: "check violation",
			err: &pgconn.PgError{
				Code: "23514",
			},
			expected: fmt.Errorf("check constraint violation: %w", &pgconn.PgError{
				Code: "23514",
			}),
		},
		{
			name:     "generic error",
			err:      assert.AnError,
			expected: fmt.Errorf("%s failed: %w", "test operation", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &authRepository{}
			err := repo.handleError(tt.err, "test operation")

			if tt.expected == domain.ErrDuplicateEmail || tt.expected == domain.ErrDuplicatePhone {
				assert.Equal(t, tt.expected, err)
			} else {
				assert.Contains(t, err.Error(), tt.expected.Error())
			}
		})
	}
}

// Helper function to create time pointer
func timePtr(t time.Time) *time.Time {
	return &t
}
