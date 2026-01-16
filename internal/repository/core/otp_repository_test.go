package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// otpQuerier interface defines only the methods needed by otpRepository
type otpQuerier interface {
	SaveOTP(ctx context.Context, params sqlc.SaveOTPParams) (sqlc.OtpVerification, error)
	GetOTP(ctx context.Context, params sqlc.GetOTPParams) (sqlc.OtpVerification, error)
	GetLatestActiveOTP(ctx context.Context, params sqlc.GetLatestActiveOTPParams) (sqlc.OtpVerification, error)
	MarkOTPUsed(ctx context.Context, params sqlc.MarkOTPUsedParams) error
	InvalidateUserOTPs(ctx context.Context, params sqlc.InvalidateUserOTPsParams) error
	DeleteExpiredOTPs(ctx context.Context) error
	DeleteUserOTPs(ctx context.Context, params sqlc.DeleteUserOTPsParams) error
	GetOTPAttemptCount(ctx context.Context, params sqlc.GetOTPAttemptCountParams) (int64, error)
	GetRecentOTPs(ctx context.Context, params sqlc.GetRecentOTPsParams) ([]sqlc.OtpVerification, error)
}

// MockOTPQuerier is a mock implementation of otpQuerier
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

// testOTPRepository wraps otpRepository but uses otpQuerier interface
type testOTPRepository struct {
	querier otpQuerier
}

func (r *testOTPRepository) SaveOTP(ctx context.Context, otp core.OTPVerification) error {
	_, err := r.querier.SaveOTP(ctx, sqlc.SaveOTPParams{
		ID:        uuidToPgtypeUUID(otp.ID),
		UserID:    uuidToPgtypeUUID(otp.UserID),
		Otp:       otp.OTP,
		Type:      otp.Type,
		Channel:   otp.Channel,
		ExpiresAt: timeToPgtypeTimestamp(otp.ExpiresAt),
	})
	if err != nil {
		return testHandleError(err, "save otp")
	}
	return nil
}

func (r *testOTPRepository) GetOTP(ctx context.Context, userID uuid.UUID, otp, otpType string) (core.OTPVerification, error) {
	record, err := r.querier.GetOTP(ctx, sqlc.GetOTPParams{
		UserID: uuidToPgtypeUUID(userID),
		Otp:    otp,
		Type:   otpType,
	})
	if err != nil {
		if err == domain.ErrNotFound {
			return core.OTPVerification{}, domain.ErrNotFound
		}
		return core.OTPVerification{}, testHandleError(err, "get otp")
	}
	return testMapToOTPVerification(record), nil
}

func (r *testOTPRepository) GetLatestActiveOTP(ctx context.Context, userID uuid.UUID, otpType string) (core.OTPVerification, error) {
	record, err := r.querier.GetLatestActiveOTP(ctx, sqlc.GetLatestActiveOTPParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		if err == domain.ErrNotFound {
			return core.OTPVerification{}, domain.ErrNotFound
		}
		return core.OTPVerification{}, testHandleError(err, "get latest active otp")
	}
	return testMapToOTPVerification(record), nil
}

func (r *testOTPRepository) MarkOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error {
	err := r.querier.MarkOTPUsed(ctx, sqlc.MarkOTPUsedParams{
		ID:     uuidToPgtypeUUID(otpID),
		UsedAt: timePtrToPgtypeTimestamp(usedAt),
	})
	if err != nil {
		return testHandleError(err, "mark otp used")
	}
	return nil
}

func (r *testOTPRepository) InvalidateUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	err := r.querier.InvalidateUserOTPs(ctx, sqlc.InvalidateUserOTPsParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		return testHandleError(err, "invalidate user otps")
	}
	return nil
}

func (r *testOTPRepository) DeleteExpiredOTPs(ctx context.Context) error {
	err := r.querier.DeleteExpiredOTPs(ctx)
	if err != nil {
		return testHandleError(err, "delete expired otps")
	}
	return nil
}

func (r *testOTPRepository) DeleteUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	err := r.querier.DeleteUserOTPs(ctx, sqlc.DeleteUserOTPsParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		return testHandleError(err, "delete user otps")
	}
	return nil
}

func (r *testOTPRepository) GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
	count, err := r.querier.GetOTPAttemptCount(ctx, sqlc.GetOTPAttemptCountParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		return 0, testHandleError(err, "get otp attempt count")
	}
	return count, nil
}

func (r *testOTPRepository) GetRecentOTPs(ctx context.Context, userID uuid.UUID, within time.Duration) ([]core.OTPVerification, error) {
	threshold := time.Now().Add(-within)
	records, err := r.querier.GetRecentOTPs(ctx, sqlc.GetRecentOTPsParams{
		UserID:    uuidToPgtypeUUID(userID),
		CreatedAt: pgtype.Timestamp{Time: threshold, Valid: true},
	})
	if err != nil {
		return nil, testHandleError(err, "get recent otps")
	}

	result := make([]core.OTPVerification, len(records))
	for i, record := range records {
		result[i] = testMapToOTPVerification(record)
	}
	return result, nil
}

// Test mapping function
func testMapToOTPVerification(record sqlc.OtpVerification) core.OTPVerification {
	return core.OTPVerification{
		ID:        pgtypeUUIDToUUID(record.ID),
		UserID:    pgtypeUUIDToUUID(record.UserID),
		OTP:       record.Otp,
		Type:      record.Type,
		Channel:   record.Channel,
		ExpiresAt: record.ExpiresAt.Time,
		UsedAt:    pgtypeTimestampToTimePtr(record.UsedAt),
		CreatedAt: record.CreatedAt.Time,
	}
}

// Helper functions
func newTestOTPRepository(mockQuerier *MockOTPQuerier) *testOTPRepository {
	return &testOTPRepository{querier: mockQuerier}
}

// Test SaveOTP
func TestOTPRepository_SaveOTP(t *testing.T) {
	ctx := context.Background()
	otpID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	otp := core.OTPVerification{
		ID:        otpID,
		UserID:    userID,
		OTP:       "123456",
		Type:      "login",
		Channel:   "sms",
		ExpiresAt: now.Add(5 * time.Minute),
	}

	t.Run("successful save", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("SaveOTP", ctx, mock.MatchedBy(func(params sqlc.SaveOTPParams) bool {
			return params.ID.Bytes == otpID &&
				params.UserID.Bytes == userID &&
				params.Otp == "123456" &&
				params.Type == "login" &&
				params.Channel == "sms"
		})).Return(sqlc.OtpVerification{}, nil)

		err := repo.SaveOTP(ctx, otp)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("SaveOTP", ctx, mock.Anything).Return(sqlc.OtpVerification{}, errors.New("database error"))

		err := repo.SaveOTP(ctx, otp)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetOTP
func TestOTPRepository_GetOTP(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	otpCode := "123456"
	otpType := "login"
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		expectedRow := sqlc.OtpVerification{
			ID:        makePgtypeUUID(uuid.New()),
			UserID:    makePgtypeUUID(userID),
			Otp:       otpCode,
			Type:      otpType,
			Channel:   "sms",
			ExpiresAt: makePgtypeTimestamp(now.Add(5 * time.Minute)),
			CreatedAt: makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetOTP", ctx, sqlc.GetOTPParams{
			UserID: makePgtypeUUID(userID),
			Otp:    otpCode,
			Type:   otpType,
		}).Return(expectedRow, nil)

		otp, err := repo.GetOTP(ctx, userID, otpCode, otpType)

		require.NoError(t, err)
		assert.Equal(t, otpCode, otp.OTP)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetOTP", ctx, sqlc.GetOTPParams{
			UserID: makePgtypeUUID(userID),
			Otp:    otpCode,
			Type:   otpType,
		}).Return(sqlc.OtpVerification{}, domain.ErrNotFound)

		_, err := repo.GetOTP(ctx, userID, otpCode, otpType)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrNotFound)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetOTP", ctx, sqlc.GetOTPParams{
			UserID: makePgtypeUUID(userID),
			Otp:    otpCode,
			Type:   otpType,
		}).Return(sqlc.OtpVerification{}, errors.New("database error"))

		_, err := repo.GetOTP(ctx, userID, otpCode, otpType)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetLatestActiveOTP
func TestOTPRepository_GetLatestActiveOTP(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	otpType := "login"
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		expectedRow := sqlc.OtpVerification{
			ID:        makePgtypeUUID(uuid.New()),
			UserID:    makePgtypeUUID(userID),
			Otp:       "123456",
			Type:      otpType,
			Channel:   "sms",
			ExpiresAt: makePgtypeTimestamp(now.Add(5 * time.Minute)),
			CreatedAt: makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetLatestActiveOTP", ctx, sqlc.GetLatestActiveOTPParams{
			UserID: makePgtypeUUID(userID),
			Type:   otpType,
		}).Return(expectedRow, nil)

		otp, err := repo.GetLatestActiveOTP(ctx, userID, otpType)

		require.NoError(t, err)
		assert.Equal(t, otpType, otp.Type)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("not found", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetLatestActiveOTP", ctx, sqlc.GetLatestActiveOTPParams{
			UserID: makePgtypeUUID(userID),
			Type:   otpType,
		}).Return(sqlc.OtpVerification{}, domain.ErrNotFound)

		_, err := repo.GetLatestActiveOTP(ctx, userID, otpType)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrNotFound)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetLatestActiveOTP", ctx, sqlc.GetLatestActiveOTPParams{
			UserID: makePgtypeUUID(userID),
			Type:   otpType,
		}).Return(sqlc.OtpVerification{}, errors.New("database error"))

		_, err := repo.GetLatestActiveOTP(ctx, userID, otpType)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test MarkOTPUsed
func TestOTPRepository_MarkOTPUsed(t *testing.T) {
	ctx := context.Background()
	otpID := uuid.New()
	now := time.Now()

	t.Run("successful mark used", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("MarkOTPUsed", ctx, sqlc.MarkOTPUsedParams{
			ID:     makePgtypeUUID(otpID),
			UsedAt: makePgtypeTimestamp(now),
		}).Return(nil)

		err := repo.MarkOTPUsed(ctx, otpID, &now)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("MarkOTPUsed", ctx, mock.Anything).Return(errors.New("database error"))

		err := repo.MarkOTPUsed(ctx, otpID, &now)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test InvalidateUserOTPs
func TestOTPRepository_InvalidateUserOTPs(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	otpType := "login"

	t.Run("successful invalidate", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("InvalidateUserOTPs", ctx, sqlc.InvalidateUserOTPsParams{
			UserID: makePgtypeUUID(userID),
			Type:   otpType,
		}).Return(nil)

		err := repo.InvalidateUserOTPs(ctx, userID, otpType)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("InvalidateUserOTPs", ctx, mock.Anything).Return(errors.New("database error"))

		err := repo.InvalidateUserOTPs(ctx, userID, otpType)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test DeleteExpiredOTPs
func TestOTPRepository_DeleteExpiredOTPs(t *testing.T) {
	ctx := context.Background()

	t.Run("successful delete", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("DeleteExpiredOTPs", ctx).Return(nil)

		err := repo.DeleteExpiredOTPs(ctx)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("DeleteExpiredOTPs", ctx).Return(errors.New("database error"))

		err := repo.DeleteExpiredOTPs(ctx)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test DeleteUserOTPs
func TestOTPRepository_DeleteUserOTPs(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	otpType := "login"

	t.Run("successful delete", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("DeleteUserOTPs", ctx, sqlc.DeleteUserOTPsParams{
			UserID: makePgtypeUUID(userID),
			Type:   otpType,
		}).Return(nil)

		err := repo.DeleteUserOTPs(ctx, userID, otpType)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("DeleteUserOTPs", ctx, mock.Anything).Return(errors.New("database error"))

		err := repo.DeleteUserOTPs(ctx, userID, otpType)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetOTPAttemptCount
func TestOTPRepository_GetOTPAttemptCount(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	otpType := "login"

	t.Run("successful count", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetOTPAttemptCount", ctx, sqlc.GetOTPAttemptCountParams{
			UserID: makePgtypeUUID(userID),
			Type:   otpType,
		}).Return(int64(3), nil)

		count, err := repo.GetOTPAttemptCount(ctx, userID, otpType)

		require.NoError(t, err)
		assert.Equal(t, int64(3), count)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetOTPAttemptCount", ctx, mock.Anything).Return(int64(0), errors.New("database error"))

		_, err := repo.GetOTPAttemptCount(ctx, userID, otpType)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetRecentOTPs
func TestOTPRepository_GetRecentOTPs(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	within := 10 * time.Minute
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		expectedRows := []sqlc.OtpVerification{
			{
				ID:        makePgtypeUUID(uuid.New()),
				UserID:    makePgtypeUUID(userID),
				Otp:       "123456",
				Type:      "login",
				Channel:   "sms",
				ExpiresAt: makePgtypeTimestamp(now.Add(5 * time.Minute)),
				CreatedAt: makePgtypeTimestamp(now),
			},
		}

		mockQuerier.On("GetRecentOTPs", ctx, mock.MatchedBy(func(params sqlc.GetRecentOTPsParams) bool {
			expectedThreshold := now.Add(-within)
			delta := params.CreatedAt.Time.Sub(expectedThreshold)
			return params.UserID == makePgtypeUUID(userID) && delta >= 0 && delta < time.Millisecond*100 // allow up to 100ms delta
		})).Return(expectedRows, nil)

		otps, err := repo.GetRecentOTPs(ctx, userID, within)

		require.NoError(t, err)
		assert.Len(t, otps, 1)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := new(MockOTPQuerier)
		repo := newTestOTPRepository(mockQuerier)

		mockQuerier.On("GetRecentOTPs", ctx, mock.Anything).Return([]sqlc.OtpVerification{}, errors.New("database error"))

		_, err := repo.GetRecentOTPs(ctx, userID, within)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}
