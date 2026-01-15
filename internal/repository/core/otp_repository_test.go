package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockOTPQuerier implements sqlc.Querier interface for OTP testing
type MockOTPQuerier struct {
	mock.Mock
}

func (m *MockOTPQuerier) SaveOTP(ctx context.Context, params sqlc.SaveOTPParams) (sqlc.OtpVerification, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(sqlc.OtpVerification), args.Error(1)
}

func (m *MockOTPQuerier) GetOTP(ctx context.Context, params sqlc.GetOTPParams) (sqlc.OtpVerification, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(sqlc.OtpVerification), args.Error(1)
}

func (m *MockOTPQuerier) GetLatestActiveOTP(ctx context.Context, params sqlc.GetLatestActiveOTPParams) (sqlc.OtpVerification, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(sqlc.OtpVerification), args.Error(1)
}

func (m *MockOTPQuerier) MarkOTPUsed(ctx context.Context, params sqlc.MarkOTPUsedParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockOTPQuerier) InvalidateUserOTPs(ctx context.Context, params sqlc.InvalidateUserOTPsParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockOTPQuerier) DeleteExpiredOTPs(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockOTPQuerier) DeleteUserOTPs(ctx context.Context, params sqlc.DeleteUserOTPsParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockOTPQuerier) GetOTPAttemptCount(ctx context.Context, params sqlc.GetOTPAttemptCountParams) (int64, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockOTPQuerier) GetRecentOTPs(ctx context.Context, params sqlc.GetRecentOTPsParams) ([]sqlc.OtpVerification, error) {
	args := m.Called(ctx, params)
	return args.Get(0).([]sqlc.OtpVerification), args.Error(1)
}

// Stub methods for other queries (just return zero values)
func (m *MockOTPQuerier) AddClinicService(ctx context.Context, params sqlc.AddClinicServiceParams) (sqlc.AddClinicServiceRow, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(sqlc.AddClinicServiceRow), args.Error(1)
}

func (m *MockOTPQuerier) CreateUser(ctx context.Context, params sqlc.CreateUserParams) (sqlc.CreateUserRow, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(sqlc.CreateUserRow), args.Error(1)
}

func (m *MockOTPQuerier) GetUserByEmail(ctx context.Context, email string) (sqlc.GetUserByEmailRow, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(sqlc.GetUserByEmailRow), args.Error(1)
}

func (m *MockOTPQuerier) GetUserByID(ctx context.Context, id pgtype.UUID) (sqlc.GetUserByIDRow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(sqlc.GetUserByIDRow), args.Error(1)
}

func (m *MockOTPQuerier) GetUserByPasswordResetToken(ctx context.Context, token pgtype.Text) (sqlc.GetUserByPasswordResetTokenRow, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(sqlc.GetUserByPasswordResetTokenRow), args.Error(1)
}

func (m *MockOTPQuerier) GetUserByPhone(ctx context.Context, phone pgtype.Text) (sqlc.GetUserByPhoneRow, error) {
	args := m.Called(ctx, phone)
	return args.Get(0).(sqlc.GetUserByPhoneRow), args.Error(1)
}

func (m *MockOTPQuerier) GetUserByPhoneWithHash(ctx context.Context, phone pgtype.Text) (sqlc.GetUserByPhoneWithHashRow, error) {
	args := m.Called(ctx, phone)
	return args.Get(0).(sqlc.GetUserByPhoneWithHashRow), args.Error(1)
}

func (m *MockOTPQuerier) GetUserByVerificationToken(ctx context.Context, token pgtype.Text) (sqlc.GetUserByVerificationTokenRow, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(sqlc.GetUserByVerificationTokenRow), args.Error(1)
}

func (m *MockOTPQuerier) UpdateUserLastLogin(ctx context.Context, id pgtype.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockOTPQuerier) UpdateUserPassword(ctx context.Context, params sqlc.UpdateUserPasswordParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockOTPQuerier) SetVerificationToken(ctx context.Context, params sqlc.SetVerificationTokenParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockOTPQuerier) SetPasswordResetToken(ctx context.Context, params sqlc.SetPasswordResetTokenParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockOTPQuerier) VerifyUser(ctx context.Context, id pgtype.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Add stubs for all other methods as needed...

func TestOTPRepository_SaveOTP(t *testing.T) {
	userID := uuid.New()
	otpID := uuid.New()
	tests := []struct {
		name      string
		otp       core.OTPVerification
		setupMock func(*MockOTPQuerier, core.OTPVerification)
		wantErr   bool
	}{
		{
			name: "successful save",
			otp: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "123456",
				Type:      "verification",
				Channel:   "sms",
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			setupMock: func(m *MockOTPQuerier, otp core.OTPVerification) {
				params := sqlc.SaveOTPParams{
					ID:        uuidToPgtypeUUID(otp.ID),
					UserID:    uuidToPgtypeUUID(otp.UserID),
					Otp:       otp.OTP,
					Type:      otp.Type,
					Channel:   otp.Channel,
					ExpiresAt: timeToPgtypeTimestamp(otp.ExpiresAt),
				}
				result := sqlc.OtpVerification{
					ID:        uuidToPgtypeUUID(otp.ID),
					UserID:    uuidToPgtypeUUID(otp.UserID),
					Otp:       otp.OTP,
					Type:      otp.Type,
					Channel:   otp.Channel,
					ExpiresAt: timeToPgtypeTimestamp(otp.ExpiresAt),
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: time.Now(), Valid: true},
				}
				m.On("SaveOTP", mock.Anything, params).Return(result, nil)
			},
			wantErr: false,
		},
		{
			name: "database error",
			otp: core.OTPVerification{
				ID:        otpID,
				UserID:    userID,
				OTP:       "123456",
				Type:      "verification",
				Channel:   "sms",
				ExpiresAt: time.Now().Add(5 * time.Minute),
			},
			setupMock: func(m *MockOTPQuerier, otp core.OTPVerification) {
				m.On("SaveOTP", mock.Anything, mock.Anything).Return(sqlc.OtpVerification{}, errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := new(MockOTPQuerier)
			tt.setupMock(mockQuerier, tt.otp)

			repo := &otpRepository{querier: mockQuerier}
			ctx := context.Background()

			err := repo.SaveOTP(ctx, tt.otp)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockQuerier.AssertExpectations(t)

			// Check metrics
			if !tt.wantErr {
				assert.Equal(t, float64(1), testutil.ToFloat64(otpDBQueryTotal.WithLabelValues("save_otp", "success")))
			} else {
				assert.Equal(t, float64(1), testutil.ToFloat64(otpDBQueryTotal.WithLabelValues("save_otp", "error")))
			}
		})
	}
}

func TestOTPRepository_GetOTP(t *testing.T) {
	userID := uuid.New()
	otp := "123456"
	otpType := "verification"

	tests := []struct {
		name      string
		setupMock func(*MockOTPQuerier)
		wantErr   bool
	}{
		{
			name: "successful get",
			setupMock: func(m *MockOTPQuerier) {
				params := sqlc.GetOTPParams{
					UserID: uuidToPgtypeUUID(userID),
					Otp:    otp,
					Type:   otpType,
				}
				result := sqlc.OtpVerification{
					ID:        uuidToPgtypeUUID(uuid.New()),
					UserID:    uuidToPgtypeUUID(userID),
					Otp:       otp,
					Type:      otpType,
					Channel:   "sms",
					ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(5 * time.Minute), Valid: true},
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: time.Now(), Valid: true},
				}
				m.On("GetOTP", mock.Anything, params).Return(result, nil)
			},
			wantErr: false,
		},
		{
			name: "not found",
			setupMock: func(m *MockOTPQuerier) {
				m.On("GetOTP", mock.Anything, mock.Anything).Return(sqlc.OtpVerification{}, pgx.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := new(MockOTPQuerier)
			tt.setupMock(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}
			ctx := context.Background()

			got, err := repo.GetOTP(ctx, userID, otp, otpType)

			if tt.wantErr {
				require.ErrorIs(t, err, domain.ErrNotFound)
			} else {
				require.NoError(t, err)
				assert.Equal(t, otp, got.OTP)
				assert.Equal(t, userID, got.UserID)
			}

			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestOTPRepository_GetLatestActiveOTP(t *testing.T) {
	userID := uuid.New()
	otpType := "verification"

	tests := []struct {
		name      string
		setupMock func(*MockOTPQuerier)
		wantErr   bool
	}{
		{
			name: "successful get latest active OTP",
			setupMock: func(m *MockOTPQuerier) {
				params := sqlc.GetLatestActiveOTPParams{
					UserID: uuidToPgtypeUUID(userID),
					Type:   otpType,
				}
				result := sqlc.OtpVerification{
					ID:        uuidToPgtypeUUID(uuid.New()),
					UserID:    uuidToPgtypeUUID(userID),
					Otp:       "654321",
					Type:      otpType,
					Channel:   "sms",
					ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(5 * time.Minute), Valid: true},
					UsedAt:    pgtype.Timestamp{Valid: false},
					CreatedAt: pgtype.Timestamp{Time: time.Now().Add(-1 * time.Minute), Valid: true},
				}
				m.On("GetLatestActiveOTP", mock.Anything, params).Return(result, nil)
			},
			wantErr: false,
		},
		{
			name: "not found",
			setupMock: func(m *MockOTPQuerier) {
				m.On("GetLatestActiveOTP", mock.Anything, mock.Anything).Return(sqlc.OtpVerification{}, pgx.ErrNoRows)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := new(MockOTPQuerier)
			tt.setupMock(mockQuerier)

			repo := &otpRepository{querier: mockQuerier}
			ctx := context.Background()

			got, err := repo.GetLatestActiveOTP(ctx, userID, otpType)

			if tt.wantErr {
				require.ErrorIs(t, err, domain.ErrNotFound)
			} else {
				require.NoError(t, err)
				assert.Equal(t, userID, got.UserID)
				assert.Equal(t, otpType, got.Type)
			}

			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestOTPRepository_GetRecentOTPs(t *testing.T) {
	userID := uuid.New()
	within := 10 * time.Minute

	tests := []struct {
		name      string
		userID    uuid.UUID
		within    time.Duration
		setupMock func(*MockOTPQuerier, uuid.UUID, time.Duration)
		wantCount int
		wantErr   bool
	}{
		{
			name:   "successful get recent OTPs",
			userID: userID,
			within: within,
			setupMock: func(m *MockOTPQuerier, userID uuid.UUID, within time.Duration) {
				threshold := time.Now().Add(-within)
				params := sqlc.GetRecentOTPsParams{
					UserID:    uuidToPgtypeUUID(userID),
					CreatedAt: pgtype.Timestamp{Time: threshold, Valid: true},
				}
				results := []sqlc.OtpVerification{
					{
						ID:        uuidToPgtypeUUID(uuid.New()),
						UserID:    uuidToPgtypeUUID(userID),
						Otp:       "123456",
						Type:      "verification",
						Channel:   "sms",
						ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(5 * time.Minute), Valid: true},
						UsedAt:    pgtype.Timestamp{Valid: false},
						CreatedAt: pgtype.Timestamp{Time: time.Now().Add(-2 * time.Minute), Valid: true},
					},
					{
						ID:        uuidToPgtypeUUID(uuid.New()),
						UserID:    uuidToPgtypeUUID(userID),
						Otp:       "654321",
						Type:      "password_reset",
						Channel:   "email",
						ExpiresAt: pgtype.Timestamp{Time: time.Now().Add(5 * time.Minute), Valid: true},
						UsedAt:    pgtype.Timestamp{Time: time.Now(), Valid: true},
						CreatedAt: pgtype.Timestamp{Time: time.Now().Add(-1 * time.Minute), Valid: true},
					},
				}
				m.On("GetRecentOTPs", mock.Anything, params).Return(results, nil)
			},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:   "no recent OTPs",
			userID: userID,
			within: within,
			setupMock: func(m *MockOTPQuerier, userID uuid.UUID, within time.Duration) {
				m.On("GetRecentOTPs", mock.Anything, mock.Anything).Return([]sqlc.OtpVerification{}, nil)
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name:   "database error",
			userID: userID,
			within: within,
			setupMock: func(m *MockOTPQuerier, userID uuid.UUID, within time.Duration) {
				m.On("GetRecentOTPs", mock.Anything, mock.Anything).Return([]sqlc.OtpVerification{}, errors.New("database error"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := new(MockOTPQuerier)
			tt.setupMock(mockQuerier, tt.userID, tt.within)

			repo := &otpRepository{querier: mockQuerier}
			ctx := context.Background()

			gotOTPs, err := repo.GetRecentOTPs(ctx, tt.userID, tt.within)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, gotOTPs, tt.wantCount)
				if tt.wantCount > 0 {
					assert.Equal(t, tt.userID, gotOTPs[0].UserID)
				}
			}

			mockQuerier.AssertExpectations(t)
		})
	}
}

// Test for MarkOTPUsed
func TestOTPRepository_MarkOTPUsed(t *testing.T) {
	otpID := uuid.New()
	usedAt := time.Now()

	tests := []struct {
		name      string
		otpID     uuid.UUID
		usedAt    *time.Time
		setupMock func(*MockOTPQuerier, uuid.UUID, *time.Time)
		wantErr   bool
	}{
		{
			name:   "successful mark OTP used",
			otpID:  otpID,
			usedAt: &usedAt,
			setupMock: func(m *MockOTPQuerier, otpID uuid.UUID, usedAt *time.Time) {
				params := sqlc.MarkOTPUsedParams{
					ID:     uuidToPgtypeUUID(otpID),
					UsedAt: pgtype.Timestamp{Time: *usedAt, Valid: true},
				}
				m.On("MarkOTPUsed", mock.Anything, params).Return(nil)
			},
			wantErr: false,
		},
		{
			name:   "database error",
			otpID:  otpID,
			usedAt: &usedAt,
			setupMock: func(m *MockOTPQuerier, otpID uuid.UUID, usedAt *time.Time) {
				m.On("MarkOTPUsed", mock.Anything, mock.Anything).Return(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := new(MockOTPQuerier)
			tt.setupMock(mockQuerier, tt.otpID, tt.usedAt)

			repo := &otpRepository{querier: mockQuerier}
			ctx := context.Background()

			err := repo.MarkOTPUsed(ctx, tt.otpID, tt.usedAt)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			mockQuerier.AssertExpectations(t)
		})
	}
}

// Test for GetOTPAttemptCount
func TestOTPRepository_GetOTPAttemptCount(t *testing.T) {
	userID := uuid.New()
	otpType := "verification"

	tests := []struct {
		name      string
		userID    uuid.UUID
		otpType   string
		setupMock func(*MockOTPQuerier, uuid.UUID, string)
		wantCount int64
		wantErr   bool
	}{
		{
			name:    "successful get attempt count",
			userID:  userID,
			otpType: otpType,
			setupMock: func(m *MockOTPQuerier, userID uuid.UUID, otpType string) {
				params := sqlc.GetOTPAttemptCountParams{
					UserID: uuidToPgtypeUUID(userID),
					Type:   otpType,
				}
				m.On("GetOTPAttemptCount", mock.Anything, params).Return(int64(3), nil)
			},
			wantCount: 3,
			wantErr:   false,
		},
		{
			name:    "database error",
			userID:  userID,
			otpType: otpType,
			setupMock: func(m *MockOTPQuerier, userID uuid.UUID, otpType string) {
				m.On("GetOTPAttemptCount", mock.Anything, mock.Anything).Return(int64(0), errors.New("database error"))
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := new(MockOTPQuerier)
			tt.setupMock(mockQuerier, tt.userID, tt.otpType)

			repo := &otpRepository{querier: mockQuerier}
			ctx := context.Background()

			count, err := repo.GetOTPAttemptCount(ctx, tt.userID, tt.otpType)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
			}

			mockQuerier.AssertExpectations(t)
		})
	}
}
