package core

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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

// Remove your manual MockQuerier struct entirely - use the generated one instead

func TestAuthRepository_CreateUser(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name          string
		user          core.User
		passwordHash  string
		mockSetup     func(*mocks.Querier) // Changed from *MockQuerier
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
			mockSetup: func(m *mocks.Querier) { // Changed from *MockQuerier
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
			mockSetup: func(m *mocks.Querier) { // Changed from *MockQuerier
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
			mockSetup: func(m *mocks.Querier) { // Changed from *MockQuerier
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
			mockSetup: func(m *mocks.Querier) { // Changed from *MockQuerier
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
			mockSetup: func(m *mocks.Querier) { // Changed from *MockQuerier
				m.On("CreateUser", ctx, mock.Anything).Return(sqlc.CreateUserRow{}, assert.AnError)
			},
			expectedUser:  core.User{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t) // Changed: use generated mock constructor
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

// Helper function
func stringPtr(s string) *string { return &s }
