// Package core
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	authDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "auth_db_query_duration_seconds",
			Help:    "Auth database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	authDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_db_query_total",
			Help: "Total number of auth database queries",
		},
		[]string{"operation", "status"},
	)
)

type authRepository struct {
	querier sqlc.Querier
}

// NewAuthRepository creates a new auth repository using a pool
func NewAuthRepository(pool *pgxpool.Pool) repository.AuthRepository {
	return NewAuthRepositoryWithQuerier(sqlc.New(pool))
}

// NewAuthRepositoryWithQuerier creates a new auth repository using a provided querier (for transactions)
func NewAuthRepositoryWithQuerier(querier sqlc.Querier) repository.AuthRepository {
	return &authRepository{
		querier: querier,
	}
}

func (r *authRepository) CreateUser(ctx context.Context, user core.User, passwordHash string) (core.User, error) {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var email string
	if user.Email != nil {
		email = *user.Email
	}

	var phone pgtype.Text
	if user.Phone != nil {
		phone = pgtype.Text{String: *user.Phone, Valid: true}
	}

	created, err := r.querier.CreateUser(ctx, sqlc.CreateUserParams{
		Email:             email,
		Phone:             phone,
		PasswordHash:      pgtype.Text{String: passwordHash, Valid: true},
		Role:              user.Role,
		Status:            pgtype.Text{String: user.Status, Valid: true},
		IsSmsOnly:         pgtype.Bool{Bool: user.IsSMSOnly, Valid: true},
		SmsConsentGiven:   pgtype.Bool{Bool: user.SMSConsentGiven, Valid: true},
		PopiaConsentGiven: pgtype.Bool{Bool: user.POPIAConsentGiven, Valid: true},
		ConsentDate:       timePtrToPgtypeTimestamp(user.ConsentDate),
	})
	if err != nil {
		authDBQueryTotal.WithLabelValues("create_user", "error").Inc()
		return core.User{}, r.handleError(err, "create user")
	}

	authDBQueryTotal.WithLabelValues("create_user", "success").Inc()
	return r.mapToUserFromCreate(created), nil
}

func (r *authRepository) GetUserByVerificationToken(ctx context.Context, token string) (core.User, string, error) {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.querier.GetUserByVerificationToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			authDBQueryTotal.WithLabelValues("get_user_by_verification_token", "not_found").Inc()
			return core.User{}, "", domain.ErrUserNotFound
		}
		authDBQueryTotal.WithLabelValues("get_user_by_verification_token", "error").Inc()
		return core.User{}, "", r.handleError(err, "get user by verification token")
	}

	authDBQueryTotal.WithLabelValues("get_user_by_verification_token", "success").Inc()

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByVerificationToken(u), passwordHash, nil
}

func (r *authRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (core.User, string, error) {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.querier.GetUserByPasswordResetToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			authDBQueryTotal.WithLabelValues("get_user_by_password_reset_token", "not_found").Inc()
			return core.User{}, "", domain.ErrUserNotFound
		}
		authDBQueryTotal.WithLabelValues("get_user_by_password_reset_token", "error").Inc()
		return core.User{}, "", r.handleError(err, "get user by password reset token")
	}

	authDBQueryTotal.WithLabelValues("get_user_by_password_reset_token", "success").Inc()

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByPasswordResetToken(u), passwordHash, nil
}

func (r *authRepository) GetUserByEmail(ctx context.Context, email string) (core.User, string, error) {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.querier.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			authDBQueryTotal.WithLabelValues("get_user_by_email", "not_found").Inc()
			return core.User{}, "", domain.ErrUserNotFound
		}
		authDBQueryTotal.WithLabelValues("get_user_by_email", "error").Inc()
		return core.User{}, "", r.handleError(err, "get user by email")
	}

	authDBQueryTotal.WithLabelValues("get_user_by_email", "success").Inc()

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByEmail(u), passwordHash, nil
}

func (r *authRepository) GetUserByPhone(ctx context.Context, phone string) (core.User, error) {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.querier.GetUserByPhone(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			authDBQueryTotal.WithLabelValues("get_user_by_phone", "not_found").Inc()
			return core.User{}, domain.ErrUserNotFound
		}
		authDBQueryTotal.WithLabelValues("get_user_by_phone", "error").Inc()
		return core.User{}, r.handleError(err, "get user by phone")
	}

	authDBQueryTotal.WithLabelValues("get_user_by_phone", "success").Inc()
	return r.mapToUserFromGetByPhone(u), nil
}

func (r *authRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (core.User, string, error) {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.querier.GetUserByPhoneWithHash(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			authDBQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "not_found").Inc()
			return core.User{}, "", domain.ErrUserNotFound
		}
		authDBQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "error").Inc()
		return core.User{}, "", r.handleError(err, "get user by phone with hash")
	}

	authDBQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "success").Inc()

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByPhoneWithHash(u), passwordHash, nil
}

func (r *authRepository) VerifyUser(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.VerifyUser(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		authDBQueryTotal.WithLabelValues("verify_user", "error").Inc()
		return r.handleError(err, "verify user")
	}

	authDBQueryTotal.WithLabelValues("verify_user", "success").Inc()
	return nil
}

func (r *authRepository) SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.SetVerificationToken(ctx, sqlc.SetVerificationTokenParams{
		ID:                  uuidToPgtypeUUID(id),
		VerificationToken:   pgtype.Text{String: token, Valid: true},
		VerificationExpires: pgtype.Timestamp{Time: expires, Valid: true},
	})
	if err != nil {
		authDBQueryTotal.WithLabelValues("set_verification_token", "error").Inc()
		return r.handleError(err, "set verification token")
	}

	authDBQueryTotal.WithLabelValues("set_verification_token", "success").Inc()
	return nil
}

func (r *authRepository) SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.SetPasswordResetToken(ctx, sqlc.SetPasswordResetTokenParams{
		ID:                   uuidToPgtypeUUID(id),
		ResetPasswordToken:   pgtype.Text{String: token, Valid: true},
		ResetPasswordExpires: pgtype.Timestamp{Time: expires, Valid: true},
	})
	if err != nil {
		authDBQueryTotal.WithLabelValues("set_password_reset_token", "error").Inc()
		return r.handleError(err, "set password reset token")
	}

	authDBQueryTotal.WithLabelValues("set_password_reset_token", "success").Inc()
	return nil
}

func (r *authRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           uuidToPgtypeUUID(id),
		PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
	})
	if err != nil {
		authDBQueryTotal.WithLabelValues("update_user_password", "error").Inc()
		return r.handleError(err, "update user password")
	}

	authDBQueryTotal.WithLabelValues("update_user_password", "success").Inc()
	return nil
}

func (r *authRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		authDBQueryTotal.WithLabelValues("update_user_status", "error").Inc()
		return r.handleError(err, "update user status")
	}

	authDBQueryTotal.WithLabelValues("update_user_status", "success").Inc()
	return nil
}

func (r *authRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		authDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserLastLogin(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		authDBQueryTotal.WithLabelValues("update_last_login", "error").Inc()
		return r.handleError(err, "update last login")
	}

	authDBQueryTotal.WithLabelValues("update_last_login", "success").Inc()
	return nil
}

// handleError converts database errors to domain errors
func (r *authRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			if strings.Contains(pgErr.ConstraintName, "email") {
				return domain.ErrDuplicateEmail
			}
			if strings.Contains(pgErr.ConstraintName, "phone") {
				return domain.ErrDuplicatePhone
			}
			return fmt.Errorf("duplicate constraint violation: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// Helper mapping functions
func (r *authRepository) mapToUserFromCreate(u sqlc.CreateUserRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      false,
		POPIAConsentGiven:    false,
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *authRepository) mapToUserFromGetByVerificationToken(u sqlc.GetUserByVerificationTokenRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		VerificationToken:    pgtypeTextToStringPtr(u.VerificationToken),
		VerificationExpires:  pgtypeTimestampToTimePtr(u.VerificationExpires),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *authRepository) mapToUserFromGetByPasswordResetToken(u sqlc.GetUserByPasswordResetTokenRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		ResetPasswordToken:   pgtypeTextToStringPtr(u.ResetPasswordToken),
		ResetPasswordExpires: pgtypeTimestampToTimePtr(u.ResetPasswordExpires),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *authRepository) mapToUserFromGetByEmail(u sqlc.GetUserByEmailRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		VerificationToken:    pgtypeTextToStringPtr(u.VerificationToken),
		VerificationExpires:  pgtypeTimestampToTimePtr(u.VerificationExpires),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *authRepository) mapToUserFromGetByPhone(u sqlc.GetUserByPhoneRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *authRepository) mapToUserFromGetByPhoneWithHash(u sqlc.GetUserByPhoneWithHashRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}
