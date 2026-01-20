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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Helper function to assert equality between two core.OTPVerification structs
func assertOTPEqual(t *testing.T, expected, got core.OTPVerification, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	assert.Equal(t, expected.UserID, got.UserID, msgAndArgs...)
	assert.Equal(t, expected.OTP, got.OTP, msgAndArgs...)
	assert.Equal(t, expected.Type, got.Type, msgAndArgs...)
	assert.Equal(t, expected.Channel, got.Channel, msgAndArgs...)
	assert.True(t, expected.ExpiresAt.Equal(got.ExpiresAt), msgAndArgs...)
	if expected.UsedAt == nil {
		assert.Nil(t, got.UsedAt, msgAndArgs...)
	} else {
		assert.NotNil(t, got.UsedAt, msgAndArgs...)
		assert.True(t, expected.UsedAt.Equal(*got.UsedAt), msgAndArgs...)
	}
	assert.True(t, expected.CreatedAt.Equal(got.CreatedAt), msgAndArgs...)
}

func TestOTPRepository_SaveOTP(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	expires := now.Add(time.Minute * 10)
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	otpID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		otp           core.OTPVerification
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful save OTP",
			otp: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "123456",
				Type:      "password_reset",
				Channel:   "sms",
				ExpiresAt: expires,
			},
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.OtpVerification{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:       "123456",
					Type:      "password_reset",
					Channel:   "sms",
					ExpiresAt: pgtype.Timestamp{Time: expires, Valid: true},
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("SaveOTP", ctx, sqlc.SaveOTPParams{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:       "123456",
					Type:      "password_reset",
					Channel:   "sms",
					ExpiresAt: pgtype.Timestamp{Time: expires, Valid: true},
				}).Return(expectedRow, nil)
			},
			expectedError: nil,
		},
		{
			name: "save OTP for email verification",
			otp: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "654321",
				Type:      "email_verification",
				Channel:   "email",
				ExpiresAt: expires,
			},
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.OtpVerification{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:       "654321",
					Type:      "email_verification",
					Channel:   "email",
					ExpiresAt: pgtype.Timestamp{Time: expires, Valid: true},
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("SaveOTP", ctx, sqlc.SaveOTPParams{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:       "654321",
					Type:      "email_verification",
					Channel:   "email",
					ExpiresAt: pgtype.Timestamp{Time: expires, Valid: true},
				}).Return(expectedRow, nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			otp: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "123456",
				Type:      "password_reset",
				Channel:   "sms",
				ExpiresAt: expires,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("SaveOTP", ctx, mock.Anything).Return(sqlc.OtpVerification{}, assert.AnError)
			},
			expectedError: fmt.Errorf("save OTP: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			err := repo.SaveOTP(ctx, tt.otp)

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

func TestOTPRepository_GetOTP(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	expires := now.Add(time.Minute * 10)
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	otpID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		otp           string
		otpType       string
		mockSetup     func(*mocks.Querier)
		expectedOTP   core.OTPVerification
		expectedError error
	}{
		{
			name:    "successful get OTP",
			userID:  userID,
			otp:     "123456",
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.OtpVerification{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:       "123456",
					Type:      "password_reset",
					Channel:   "sms",
					ExpiresAt: pgtype.Timestamp{Time: expires, Valid: true},
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetOTP", ctx, sqlc.GetOTPParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:    "123456",
					Type:   "password_reset",
				}).Return(expectedRow, nil)
			},
			expectedOTP: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "123456",
				Type:      "password_reset",
				Channel:   "sms",
				ExpiresAt: expires,
				UsedAt:    nil,
				CreatedAt: now,
			},
			expectedError: nil,
		},
		{
			name:    "OTP not found",
			userID:  userID,
			otp:     "999999",
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetOTP", ctx, sqlc.GetOTPParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:    "999999",
					Type:   "password_reset",
				}).Return(sqlc.OtpVerification{}, pgx.ErrNoRows)
			},
			expectedOTP:   core.OTPVerification{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:    "database error",
			userID:  userID,
			otp:     "123456",
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetOTP", ctx, mock.Anything).Return(sqlc.OtpVerification{}, assert.AnError)
			},
			expectedOTP:   core.OTPVerification{},
			expectedError: fmt.Errorf("get OTP: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			gotOTP, err := repo.GetOTP(ctx, tt.userID, tt.otp, tt.otpType)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == domain.ErrNotFound {
					assert.Equal(t, domain.ErrNotFound, err)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
				assertOTPEqual(t, tt.expectedOTP, gotOTP)
			} else {
				require.NoError(t, err)
				assertOTPEqual(t, tt.expectedOTP, gotOTP)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestOTPRepository_GetLatestActiveOTP(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	expires := now.Add(time.Minute * 10)
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	otpID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		otpType       string
		mockSetup     func(*mocks.Querier)
		expectedOTP   core.OTPVerification
		expectedError error
	}{
		{
			name:    "successful get latest active OTP",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.OtpVerification{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Otp:       "123456",
					Type:      "password_reset",
					Channel:   "sms",
					ExpiresAt: pgtype.Timestamp{Time: expires, Valid: true},
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetLatestActiveOTP", ctx, sqlc.GetLatestActiveOTPParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Type:   "password_reset",
				}).Return(expectedRow, nil)
			},
			expectedOTP: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "123456",
				Type:      "password_reset",
				Channel:   "sms",
				ExpiresAt: expires,
				UsedAt:    nil,
				CreatedAt: now,
			},
			expectedError: nil,
		},
		{
			name:    "no active OTP found",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetLatestActiveOTP", ctx, sqlc.GetLatestActiveOTPParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Type:   "password_reset",
				}).Return(sqlc.OtpVerification{}, pgx.ErrNoRows)
			},
			expectedOTP:   core.OTPVerification{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:    "database error",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetLatestActiveOTP", ctx, mock.Anything).Return(sqlc.OtpVerification{}, assert.AnError)
			},
			expectedOTP:   core.OTPVerification{},
			expectedError: fmt.Errorf("get latest active OTP: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			gotOTP, err := repo.GetLatestActiveOTP(ctx, tt.userID, tt.otpType)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == domain.ErrNotFound {
					assert.Equal(t, domain.ErrNotFound, err)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
				assertOTPEqual(t, tt.expectedOTP, gotOTP)
			} else {
				require.NoError(t, err)
				assertOTPEqual(t, tt.expectedOTP, gotOTP)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestOTPRepository_MarkOTPUsed(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	otpID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		otpID         uuid.UUID
		usedAt        *time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful mark OTP used with timestamp",
			otpID:  otpID,
			usedAt: &now,
			mockSetup: func(m *mocks.Querier) {
				m.On("MarkOTPUsed", ctx, sqlc.MarkOTPUsedParams{
					ID:     uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UsedAt: pgtype.Timestamp{Time: now, Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "successful mark OTP used without timestamp",
			otpID:  otpID,
			usedAt: nil,
			mockSetup: func(m *mocks.Querier) {
				m.On("MarkOTPUsed", ctx, sqlc.MarkOTPUsedParams{
					ID:     uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UsedAt: pgtype.Timestamp{Valid: false},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			otpID:  otpID,
			usedAt: &now,
			mockSetup: func(m *mocks.Querier) {
				m.On("MarkOTPUsed", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("mark OTP used: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			err := repo.MarkOTPUsed(ctx, tt.otpID, tt.usedAt)

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

func TestOTPRepository_InvalidateUserOTPs(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		otpType       string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful invalidate user OTPs",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("InvalidateUserOTPs", ctx, sqlc.InvalidateUserOTPsParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Type:   "password_reset",
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("InvalidateUserOTPs", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("invalidate user OTPs: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			err := repo.InvalidateUserOTPs(ctx, tt.userID, tt.otpType)

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

func TestOTPRepository_DeleteExpiredOTPs(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful delete expired OTPs",
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteExpiredOTPs", ctx).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteExpiredOTPs", ctx).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("delete expired OTPs: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			err := repo.DeleteExpiredOTPs(ctx)

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

func TestOTPRepository_DeleteUserOTPs(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		otpType       string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful delete user OTPs",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteUserOTPs", ctx, sqlc.DeleteUserOTPsParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Type:   "password_reset",
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteUserOTPs", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("delete user OTPs: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			err := repo.DeleteUserOTPs(ctx, tt.userID, tt.otpType)

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

func TestOTPRepository_GetOTPAttemptCount(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		otpType       string
		mockSetup     func(*mocks.Querier)
		expectedCount int64
		expectedError error
	}{
		{
			name:    "successful get OTP attempt count",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetOTPAttemptCount", ctx, sqlc.GetOTPAttemptCountParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Type:   "password_reset",
				}).Return(int64(3), nil)
			},
			expectedCount: 3,
			expectedError: nil,
		},
		{
			name:    "zero attempts",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetOTPAttemptCount", ctx, sqlc.GetOTPAttemptCountParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Type:   "password_reset",
				}).Return(int64(0), nil)
			},
			expectedCount: 0,
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			otpType: "password_reset",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetOTPAttemptCount", ctx, mock.Anything).Return(int64(0), assert.AnError)
			},
			expectedCount: 0,
			expectedError: fmt.Errorf("get OTP attempt count: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}

			gotCount, err := repo.GetOTPAttemptCount(ctx, tt.userID, tt.otpType)

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

func TestOTPRepository_GetRecentOTPs(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	otpID1 := uuid.MustParse("223e4567-e89b-12d3-a456-426614174001")
	otpID2 := uuid.MustParse("223e4567-e89b-12d3-a456-426614174002")
	within := time.Hour * 1
	threshold := now.Add(-within)

	tests := []struct {
		name          string
		userID        uuid.UUID
		within        time.Duration
		mockSetup     func(*mocks.Querier, time.Time)
		expectedOTPs  []core.OTPVerification
		expectedError error
	}{
		{
			name:   "successful get recent OTPs",
			userID: userID,
			within: within,
			mockSetup: func(m *mocks.Querier, threshold time.Time) {
				// Use mock.MatchedBy to handle time differences flexibly
				expectedRows := []sqlc.OtpVerification{
					{
						ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174001"),
						UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						Otp:       "111111",
						Type:      "password_reset",
						Channel:   "sms",
						ExpiresAt: pgtype.Timestamp{Time: now.Add(time.Minute * 5), Valid: true},
						UsedAt:    pgtype.Timestamp{Valid: false},
						CreatedAt: pgtype.Timestamp{Time: now.Add(-time.Minute * 30), Valid: true},
					},
					{
						ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174002"),
						UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						Otp:       "222222",
						Type:      "email_verification",
						Channel:   "email",
						ExpiresAt: pgtype.Timestamp{Time: now.Add(time.Minute * 10), Valid: true},
						UsedAt:    pgtype.Timestamp{Time: now.Add(-time.Minute * 5), Valid: true},
						CreatedAt: pgtype.Timestamp{Time: now.Add(-time.Minute * 45), Valid: true},
					},
				}
				// Use mock.MatchedBy to accept any timestamp within 1 second of the threshold
				m.On("GetRecentOTPs", ctx, mock.MatchedBy(func(p sqlc.GetRecentOTPsParams) bool {
					// Check if UserID matches
					if p.UserID.Bytes != userID {
						return false
					}
					// Check if CreatedAt is within 1 second of threshold
					timeDiff := p.CreatedAt.Time.Sub(threshold).Abs()
					return timeDiff <= time.Second
				})).Return(expectedRows, nil)
			},
			expectedOTPs: []core.OTPVerification{
				{
					ID:        otpID1,
					UserID:    userID,
					OTP:       "111111",
					Type:      "password_reset",
					Channel:   "sms",
					ExpiresAt: now.Add(time.Minute * 5),
					UsedAt:    nil,
					CreatedAt: now.Add(-time.Minute * 30),
				},
				{
					ID:        otpID2,
					UserID:    userID,
					OTP:       "222222",
					Type:      "email_verification",
					Channel:   "email",
					ExpiresAt: now.Add(time.Minute * 10),
					UsedAt:    timePtr(now.Add(-time.Minute * 5)),
					CreatedAt: now.Add(-time.Minute * 45),
				},
			},
			expectedError: nil,
		},
		{
			name:   "no recent OTPs",
			userID: userID,
			within: within,
			mockSetup: func(m *mocks.Querier, threshold time.Time) {
				// Use mock.MatchedBy to handle time differences flexibly
				m.On("GetRecentOTPs", ctx, mock.MatchedBy(func(p sqlc.GetRecentOTPsParams) bool {
					// Check if UserID matches
					if p.UserID.Bytes != userID {
						return false
					}
					// Check if CreatedAt is within 1 second of threshold
					timeDiff := p.CreatedAt.Time.Sub(threshold).Abs()
					return timeDiff <= time.Second
				})).Return([]sqlc.OtpVerification{}, nil)
			},
			expectedOTPs:  []core.OTPVerification{},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: userID,
			within: within,
			mockSetup: func(m *mocks.Querier, threshold time.Time) {
				m.On("GetRecentOTPs", ctx, mock.Anything).Return([]sqlc.OtpVerification{}, assert.AnError)
			},
			expectedOTPs:  nil,
			expectedError: fmt.Errorf("get recent OTPs: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier, threshold)

			repo := &otpRepository{querier: mockQuerier}

			gotOTPs, err := repo.GetRecentOTPs(ctx, tt.userID, tt.within)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotOTPs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedOTPs), len(gotOTPs))
				for i, expectedOTP := range tt.expectedOTPs {
					assert.Equal(t, expectedOTP.ID, gotOTPs[i].ID, "OTP ID mismatch")
					assert.Equal(t, expectedOTP.UserID, gotOTPs[i].UserID, "User ID mismatch")
					assert.Equal(t, expectedOTP.OTP, gotOTPs[i].OTP, "OTP code mismatch")
					assert.Equal(t, expectedOTP.Type, gotOTPs[i].Type, "OTP type mismatch")
					assert.Equal(t, expectedOTP.Channel, gotOTPs[i].Channel, "OTP channel mismatch")

					// Use WithinDuration for time comparisons to allow small differences
					assert.WithinDuration(t, expectedOTP.ExpiresAt, gotOTPs[i].ExpiresAt, time.Second, "ExpiresAt time mismatch")
					assert.WithinDuration(t, expectedOTP.CreatedAt, gotOTPs[i].CreatedAt, time.Second, "CreatedAt time mismatch")

					if expectedOTP.UsedAt == nil {
						assert.Nil(t, gotOTPs[i].UsedAt, "Expected UsedAt to be nil")
					} else {
						require.NotNil(t, gotOTPs[i].UsedAt, "Expected UsedAt to not be nil")
						assert.WithinDuration(t, *expectedOTP.UsedAt, *gotOTPs[i].UsedAt, time.Second, "UsedAt time mismatch")
					}
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
