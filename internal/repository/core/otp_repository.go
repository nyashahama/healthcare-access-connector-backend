package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	otpDbQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "otp_db_query_duration_seconds",
			Help:    "OTP database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	otpDbQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "otp_db_query_total",
			Help: "Total number of OTP database queries",
		},
		[]string{"operation", "status"},
	)
)

type otpRepository struct {
	querier sqlc.Querier
}

// NewOTPRepository creates a new OTP repository using a pool
func NewOTPRepository(pool *pgxpool.Pool) repository.OTPRepository {
	return NewOTPRepositoryWithQuerier(sqlc.New(pool))
}

// NewOTPRepositoryWithQuerier creates a new OTP repository using a provided querier (for transactions)
func NewOTPRepositoryWithQuerier(querier sqlc.Querier) repository.OTPRepository {
	return &otpRepository{
		querier: querier,
	}
}

func (r *otpRepository) SaveOTP(ctx context.Context, otp core.OTPVerification) error {
	start := time.Now()
	defer func() {
		otpDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	_, err := r.querier.SaveOTP(ctx, sqlc.SaveOTPParams{
		ID:        uuidToPgtypeUUID(otp.ID),
		UserID:    uuidToPgtypeUUID(otp.UserID),
		Otp:       otp.OTP,
		Type:      otp.Type,
		Channel:   otp.Channel,
		ExpiresAt: timeToPgtypeTimestamp(otp.ExpiresAt),
	})
	if err != nil {
		otpDbQueryTotal.WithLabelValues("save_otp", "error").Inc()
		return fmt.Errorf("save OTP: %w", err)
	}

	otpDbQueryTotal.WithLabelValues("save_otp", "success").Inc()
	return nil
}

func (r *otpRepository) GetOTP(ctx context.Context, userID uuid.UUID, otp, otpType string) (core.OTPVerification, error) {
	start := time.Now()
	defer func() {
		otpDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	record, err := r.querier.GetOTP(ctx, sqlc.GetOTPParams{
		UserID: uuidToPgtypeUUID(userID),
		Otp:    otp,
		Type:   otpType,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			otpDbQueryTotal.WithLabelValues("get_otp", "not_found").Inc()
			return core.OTPVerification{}, domain.ErrNotFound
		}
		otpDbQueryTotal.WithLabelValues("get_otp", "error").Inc()
		return core.OTPVerification{}, fmt.Errorf("get OTP: %w", err)
	}

	otpDbQueryTotal.WithLabelValues("get_otp", "success").Inc()

	return core.OTPVerification{
		ID:        pgtypeUUIDToUUID(record.ID),
		UserID:    pgtypeUUIDToUUID(record.UserID),
		OTP:       record.Otp,
		Type:      record.Type,
		Channel:   record.Channel,
		ExpiresAt: record.ExpiresAt.Time,
		UsedAt:    pgtypeTimestampToTimePtr(record.UsedAt),
		CreatedAt: record.CreatedAt.Time,
	}, nil
}

func (r *otpRepository) MarkOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error {
	start := time.Now()
	defer func() {
		otpDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.MarkOTPUsed(ctx, sqlc.MarkOTPUsedParams{
		ID:     uuidToPgtypeUUID(otpID),
		UsedAt: timePtrToPgtypeTimestamp(usedAt),
	})
	if err != nil {
		otpDbQueryTotal.WithLabelValues("mark_otp_used", "error").Inc()
		return fmt.Errorf("mark OTP used: %w", err)
	}

	otpDbQueryTotal.WithLabelValues("mark_otp_used", "success").Inc()
	return nil
}

func (r *otpRepository) DeleteExpiredOTPs(ctx context.Context) error {
	start := time.Now()
	defer func() {
		otpDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteExpiredOTPs(ctx)
	if err != nil {
		otpDbQueryTotal.WithLabelValues("delete_expired_otps", "error").Inc()
		return fmt.Errorf("delete expired OTPs: %w", err)
	}

	otpDbQueryTotal.WithLabelValues("delete_expired_otps", "success").Inc()
	return nil
}

func (r *otpRepository) DeleteUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	start := time.Now()
	defer func() {
		otpDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteUserOTPs(ctx, sqlc.DeleteUserOTPsParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		otpDbQueryTotal.WithLabelValues("delete_user_otps", "error").Inc()
		return fmt.Errorf("delete user OTPs: %w", err)
	}

	otpDbQueryTotal.WithLabelValues("delete_user_otps", "success").Inc()
	return nil
}

func (r *otpRepository) GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
	start := time.Now()
	defer func() {
		otpDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.querier.GetOTPAttemptCount(ctx, sqlc.GetOTPAttemptCountParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		otpDbQueryTotal.WithLabelValues("get_otp_attempt_count", "error").Inc()
		return 0, fmt.Errorf("get OTP attempt count: %w", err)
	}

	otpDbQueryTotal.WithLabelValues("get_otp_attempt_count", "success").Inc()
	return count, nil
}
