// Package repository implements data access layer
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository/pgutils"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository/sqlc"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	dbQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	dbQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "db_query_total",
			Help: "Total number of database queries",
		},
		[]string{"operation", "status"},
	)
)

type userRepository struct {
	db *sqlc.Queries
}

// NewUserRepository creates a new user repository
func NewUserRepository(pool *pgxpool.Pool) UserRepository {
	return &userRepository{
		db: sqlc.New(pool),
	}
}

func (r *userRepository) CreateUser(ctx context.Context, user domain.User, passwordHash string) (domain.User, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.db.CreateUser(ctx, sqlc.CreateUserParams{
		Email:             pgutils.StringFromPtr(user.Email),
		Phone:             pgutils.TextFromPtr(user.Phone),
		PasswordHash:      pgutils.TextFrom(passwordHash),
		Role:              user.Role,
		Status:            pgutils.TextFrom(user.Status),
		IsSmsOnly:         pgutils.BoolFrom(user.IsSMSOnly),
		SmsConsentGiven:   pgutils.BoolFrom(user.SMSConsentGiven),
		PopiaConsentGiven: pgutils.BoolFrom(user.POPIAConsentGiven),
		ConsentDate:       pgutils.TimestampFromPtr(user.ConsentDate),
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("create_user", "error").Inc()
		return domain.User{}, r.handleError(err, "create user")
	}

	dbQueryTotal.WithLabelValues("create_user", "success").Inc()
	return r.mapUser(userRow{
		ID:                          created.ID,
		Email:                       created.Email,
		Phone:                       created.Phone,
		Role:                        created.Role,
		Status:                      created.Status,
		IsVerified:                  created.IsVerified,
		LastLogin:                   created.LastLogin,
		LoginCount:                  created.LoginCount,
		IsSmsOnly:                   created.IsSmsOnly,
		ProfileCompletionPercentage: created.ProfileCompletionPercentage,
		CreatedAt:                   created.CreatedAt,
		UpdatedAt:                   created.UpdatedAt,
	}), nil
}

// GetUserByVerificationToken gets user by verification token
func (r *userRepository) GetUserByVerificationToken(ctx context.Context, token string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByVerificationToken(ctx, pgutils.TextFrom(token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_verification_token", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_verification_token", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by verification token")
	}

	dbQueryTotal.WithLabelValues("get_user_by_verification_token", "success").Inc()
	return r.mapUser(userRow{
		ID:                          u.ID,
		Email:                       u.Email,
		Phone:                       u.Phone,
		Role:                        u.Role,
		Status:                      u.Status,
		IsVerified:                  u.IsVerified,
		VerificationToken:           u.VerificationToken,
		VerificationExpires:         u.VerificationExpires,
		LastLogin:                   u.LastLogin,
		LoginCount:                  u.LoginCount,
		IsSmsOnly:                   u.IsSmsOnly,
		SmsConsentGiven:             u.SmsConsentGiven,
		PopiaConsentGiven:           u.PopiaConsentGiven,
		ProfileCompletionPercentage: u.ProfileCompletionPercentage,
		CreatedAt:                   u.CreatedAt,
		UpdatedAt:                   u.UpdatedAt,
	}), pgutils.TextToString(u.PasswordHash), nil
}

// GetUserByPasswordResetToken gets user by password reset token
func (r *userRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByPasswordResetToken(ctx, pgutils.TextFrom(token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_password_reset_token", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_password_reset_token", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by password reset token")
	}

	dbQueryTotal.WithLabelValues("get_user_by_password_reset_token", "success").Inc()
	return r.mapUser(userRow{
		ID:                          u.ID,
		Email:                       u.Email,
		Phone:                       u.Phone,
		Role:                        u.Role,
		Status:                      u.Status,
		IsVerified:                  u.IsVerified,
		ResetPasswordToken:          u.ResetPasswordToken,
		ResetPasswordExpires:        u.ResetPasswordExpires,
		LastLogin:                   u.LastLogin,
		LoginCount:                  u.LoginCount,
		IsSmsOnly:                   u.IsSmsOnly,
		SmsConsentGiven:             u.SmsConsentGiven,
		PopiaConsentGiven:           u.PopiaConsentGiven,
		ProfileCompletionPercentage: u.ProfileCompletionPercentage,
		CreatedAt:                   u.CreatedAt,
		UpdatedAt:                   u.UpdatedAt,
	}), pgutils.TextToString(u.PasswordHash), nil
}

func (r *userRepository) GetUserByEmail(ctx context.Context, email string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_email", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_email", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by email")
	}

	dbQueryTotal.WithLabelValues("get_user_by_email", "success").Inc()
	return r.mapUser(userRow{
		ID:                          u.ID,
		Email:                       u.Email,
		Phone:                       u.Phone,
		Role:                        u.Role,
		Status:                      u.Status,
		IsVerified:                  u.IsVerified,
		VerificationToken:           u.VerificationToken,
		VerificationExpires:         u.VerificationExpires,
		LastLogin:                   u.LastLogin,
		LoginCount:                  u.LoginCount,
		IsSmsOnly:                   u.IsSmsOnly,
		SmsConsentGiven:             u.SmsConsentGiven,
		PopiaConsentGiven:           u.PopiaConsentGiven,
		ProfileCompletionPercentage: u.ProfileCompletionPercentage,
		CreatedAt:                   u.CreatedAt,
		UpdatedAt:                   u.UpdatedAt,
	}), pgutils.TextToString(u.PasswordHash), nil
}

func (r *userRepository) GetUserByPhone(ctx context.Context, phone string) (domain.User, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByPhone(ctx, pgutils.TextFrom(phone))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_phone", "not_found").Inc()
			return domain.User{}, domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_phone", "error").Inc()
		return domain.User{}, r.handleError(err, "get user by phone")
	}

	dbQueryTotal.WithLabelValues("get_user_by_phone", "success").Inc()
	return r.mapUser(userRow{
		ID:                          u.ID,
		Email:                       u.Email,
		Phone:                       u.Phone,
		Role:                        u.Role,
		Status:                      u.Status,
		IsVerified:                  u.IsVerified,
		LastLogin:                   u.LastLogin,
		LoginCount:                  u.LoginCount,
		IsSmsOnly:                   u.IsSmsOnly,
		SmsConsentGiven:             u.SmsConsentGiven,
		PopiaConsentGiven:           u.PopiaConsentGiven,
		ProfileCompletionPercentage: u.ProfileCompletionPercentage,
		CreatedAt:                   u.CreatedAt,
		UpdatedAt:                   u.UpdatedAt,
	}), nil
}

func (r *userRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByPhoneWithHash(ctx, pgutils.TextFrom(phone))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by phone with hash")
	}

	dbQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "success").Inc()
	return r.mapUser(userRow{
		ID:                          u.ID,
		Email:                       u.Email,
		Phone:                       u.Phone,
		Role:                        u.Role,
		Status:                      u.Status,
		IsVerified:                  u.IsVerified,
		LastLogin:                   u.LastLogin,
		LoginCount:                  u.LoginCount,
		IsSmsOnly:                   u.IsSmsOnly,
		SmsConsentGiven:             u.SmsConsentGiven,
		PopiaConsentGiven:           u.PopiaConsentGiven,
		ProfileCompletionPercentage: u.ProfileCompletionPercentage,
		CreatedAt:                   u.CreatedAt,
		UpdatedAt:                   u.UpdatedAt,
	}), pgutils.TextToString(u.PasswordHash), nil
}

func (r *userRepository) GetUserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert uuid.UUID to pgtype.UUID
	pgID := uuidToPgtypeUUID(id)

	u, err := r.db.GetUserByID(ctx, pgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_id", "not_found").Inc()
			return domain.User{}, domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_id", "error").Inc()
		return domain.User{}, r.handleError(err, "get user by id")
	}

	dbQueryTotal.WithLabelValues("get_user_by_id", "success").Inc()

	return r.mapToUserFromGetByID(u), nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user domain.User) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// This is a placeholder - you'll need to add specific update queries in queries.sql
	// For now, return not implemented
	dbQueryTotal.WithLabelValues("update_user", "error").Inc()
	return fmt.Errorf("not implemented")
}

func (r *userRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("update_user_status", "error").Inc()
		return r.handleError(err, "update user status")
	}

	dbQueryTotal.WithLabelValues("update_user_status", "success").Inc()
	return nil
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.UpdateUserLastLogin(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		dbQueryTotal.WithLabelValues("update_last_login", "error").Inc()
		return r.handleError(err, "update last login")
	}

	dbQueryTotal.WithLabelValues("update_last_login", "success").Inc()
	return nil
}

func (r *userRepository) VerifyUser(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.VerifyUser(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		dbQueryTotal.WithLabelValues("verify_user", "error").Inc()
		return r.handleError(err, "verify user")
	}

	dbQueryTotal.WithLabelValues("verify_user", "success").Inc()
	return nil
}

// SetVerificationToken sets verification token for a user
func (r *userRepository) SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.SetVerificationToken(ctx, sqlc.SetVerificationTokenParams{
		ID:                  uuidToPgtypeUUID(id),
		VerificationToken:   pgtype.Text{String: token, Valid: true},
		VerificationExpires: pgtype.Timestamp{Time: expires, Valid: true},
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("set_verification_token", "error").Inc()
		return r.handleError(err, "set verification token")
	}

	dbQueryTotal.WithLabelValues("set_verification_token", "success").Inc()
	return nil
}

// SetPasswordResetToken sets password reset token for a user
func (r *userRepository) SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.SetPasswordResetToken(ctx, sqlc.SetPasswordResetTokenParams{
		ID:                   uuidToPgtypeUUID(id),
		ResetPasswordToken:   pgtype.Text{String: token, Valid: true},
		ResetPasswordExpires: pgtype.Timestamp{Time: expires, Valid: true},
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("set_password_reset_token", "error").Inc()
		return r.handleError(err, "set password reset token")
	}

	dbQueryTotal.WithLabelValues("set_password_reset_token", "success").Inc()
	return nil
}

// UpdateUserPassword updates user password and clears reset token
func (r *userRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           uuidToPgtypeUUID(id),
		PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("update_user_password", "error").Inc()
		return r.handleError(err, "update user password")
	}

	dbQueryTotal.WithLabelValues("update_user_password", "success").Inc()
	return nil
}

func (r *userRepository) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: "inactive", Valid: true},
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("deactivate_user", "error").Inc()
		return r.handleError(err, "deactivate user")
	}

	dbQueryTotal.WithLabelValues("deactivate_user", "success").Inc()
	return nil
}

func (r *userRepository) ListUsers(ctx context.Context, role string, limit, offset int) ([]domain.User, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	users, err := r.db.ListUsersByRole(ctx, sqlc.ListUsersByRoleParams{
		Role:   role,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("list_users", "error").Inc()
		return nil, r.handleError(err, "list users")
	}

	dbQueryTotal.WithLabelValues("list_users", "success").Inc()

	result := make([]domain.User, len(users))
	for i, u := range users {
		result[i] = r.mapToUserFromList(u)
	}

	return result, nil
}

func (r *userRepository) CountUsers(ctx context.Context, role string) (int64, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.db.CountUsersByRole(ctx, role)
	if err != nil {
		dbQueryTotal.WithLabelValues("count_users", "error").Inc()
		return 0, r.handleError(err, "count users")
	}

	dbQueryTotal.WithLabelValues("count_users", "success").Inc()
	return count, nil
}

// SaveOTP saves an OTP verification record
func (r *userRepository) SaveOTP(ctx context.Context, otp domain.OTPVerification) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	_, err := r.db.SaveOTP(ctx, sqlc.SaveOTPParams{
		ID:        uuidToPgtypeUUID(otp.ID),
		UserID:    uuidToPgtypeUUID(otp.UserID),
		Otp:       otp.OTP,
		Type:      otp.Type,
		Channel:   otp.Channel,
		ExpiresAt: timeToPgtypeTimestamp(otp.ExpiresAt),
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("save_otp", "error").Inc()
		return r.handleError(err, "save OTP")
	}

	dbQueryTotal.WithLabelValues("save_otp", "success").Inc()
	return nil
}

// GetOTP retrieves an OTP verification record
func (r *userRepository) GetOTP(ctx context.Context, userID uuid.UUID, otp, otpType string) (domain.OTPVerification, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	record, err := r.db.GetOTP(ctx, sqlc.GetOTPParams{
		UserID: uuidToPgtypeUUID(userID),
		Otp:    otp,
		Type:   otpType,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_otp", "not_found").Inc()
			return domain.OTPVerification{}, domain.ErrNotFound
		}
		dbQueryTotal.WithLabelValues("get_otp", "error").Inc()
		return domain.OTPVerification{}, r.handleError(err, "get OTP")
	}

	dbQueryTotal.WithLabelValues("get_otp", "success").Inc()

	return domain.OTPVerification{
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

// MarkOTPUsed marks an OTP as used
func (r *userRepository) MarkOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.MarkOTPUsed(ctx, sqlc.MarkOTPUsedParams{
		ID:     uuidToPgtypeUUID(otpID),
		UsedAt: timePtrToPgtypeTimestamp(usedAt),
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("mark_otp_used", "error").Inc()
		return r.handleError(err, "mark OTP used")
	}

	dbQueryTotal.WithLabelValues("mark_otp_used", "success").Inc()
	return nil
}

// DeleteExpiredOTPs deletes expired OTP records
func (r *userRepository) DeleteExpiredOTPs(ctx context.Context) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.DeleteExpiredOTPs(ctx)
	if err != nil {
		dbQueryTotal.WithLabelValues("delete_expired_otps", "error").Inc()
		return r.handleError(err, "delete expired OTPs")
	}

	dbQueryTotal.WithLabelValues("delete_expired_otps", "success").Inc()
	return nil
}

// DeleteUserOTPs deletes all OTPs for a user and type
func (r *userRepository) DeleteUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.db.DeleteUserOTPs(ctx, sqlc.DeleteUserOTPsParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("delete_user_otps", "error").Inc()
		return r.handleError(err, "delete user OTPs")
	}

	dbQueryTotal.WithLabelValues("delete_user_otps", "success").Inc()
	return nil
}

// GetOTPAttemptCount gets the number of OTP attempts in the last hour
func (r *userRepository) GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.db.GetOTPAttemptCount(ctx, sqlc.GetOTPAttemptCountParams{
		UserID: uuidToPgtypeUUID(userID),
		Type:   otpType,
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("get_otp_attempt_count", "error").Inc()
		return 0, r.handleError(err, "get OTP attempt count")
	}

	dbQueryTotal.WithLabelValues("get_otp_attempt_count", "success").Inc()
	return count, nil
}

// handleError converts database errors to domain errors
func (r *userRepository) handleError(err error, operation string) error {
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

// ========================================
// SINGLE mapping function using userRow
// ========================================

// userRow is an intermediate struct that normalizes all sqlc row types
// This allows us to have ONE mapping function instead of 8+
type userRow struct {
	ID                          interface{}
	Email                       interface{}
	Phone                       interface{}
	Role                        string
	Status                      interface{}
	IsVerified                  interface{}
	VerificationToken           interface{}
	VerificationExpires         interface{}
	ResetPasswordToken          interface{}
	ResetPasswordExpires        interface{}
	LastLogin                   interface{}
	LoginCount                  interface{}
	IsSmsOnly                   interface{}
	SmsConsentGiven             interface{}
	PopiaConsentGiven           interface{}
	ProfileCompletionPercentage interface{}
	CreatedAt                   interface{}
	UpdatedAt                   interface{}
}

func (r *userRepository) mapUser(row userRow) domain.User {
	return domain.User{
		ID:                   pgutils.UUIDTo(row.ID.(pgtype.UUID)),
		Email:                pgutils.StringToPtr(row.Email.(string)),
		Phone:                pgutils.TextToPtr(row.Phone.(pgtype.Text)),
		Role:                 row.Role,
		Status:               pgutils.TextToString(row.Status.(pgtype.Text)),
		IsVerified:           pgutils.BoolTo(row.IsVerified.(pgtype.Bool)),
		VerificationToken:    r.optionalTextToPtr(row.VerificationToken),
		VerificationExpires:  r.optionalTimestampToPtr(row.VerificationExpires),
		ResetPasswordToken:   r.optionalTextToPtr(row.ResetPasswordToken),
		ResetPasswordExpires: r.optionalTimestampToPtr(row.ResetPasswordExpires),
		LastLogin:            r.optionalTimestampToPtr(row.LastLogin),
		LoginCount:           r.optionalInt32ToInt(row.LoginCount),
		IsSMSOnly:            r.optionalBool(row.IsSmsOnly),
		SMSConsentGiven:      r.optionalBool(row.SmsConsentGiven),
		POPIAConsentGiven:    r.optionalBool(row.PopiaConsentGiven),
		ProfileCompletionPct: r.optionalInt32ToInt(row.ProfileCompletionPercentage),
		CreatedAt:            r.requiredTimestamp(row.CreatedAt),
		UpdatedAt:            r.optionalTimestamp(row.UpdatedAt),
	}
}

// Helper methods for handling optional fields in the mapping

func (r *userRepository) optionalTextToPtr(v interface{}) *string {
	if v == nil {
		return nil
	}
	return pgutils.TextToPtr(v.(pgtype.Text))
}

func (r *userRepository) optionalTimestampToPtr(v interface{}) *time.Time {
	if v == nil {
		return nil
	}
	return pgutils.TimestampToPtr(v.(pgtype.Timestamp))
}

func (r *userRepository) optionalTimestamp(v interface{}) time.Time {
	if v == nil {
		return time.Time{}
	}
	return pgutils.TimestampTo(v.(pgtype.Timestamp))
}

func (r *userRepository) requiredTimestamp(v interface{}) time.Time {
	// This should never be nil for CreatedAt, but we handle it just in case
	if v == nil {
		return time.Time{}
	}
	return pgutils.TimestampTo(v.(pgtype.Timestamp))
}

func (r *userRepository) optionalInt32ToInt(v interface{}) int {
	if v == nil {
		return 0
	}
	pgInt4, ok := v.(pgtype.Int4)
	if ok {
		return int(pgutils.Int4To(pgInt4))
	}

	// Some might be pgtype.Int8, try that too
	pgInt8, ok := v.(pgtype.Int8)
	if ok {
		return int(pgutils.Int8To(pgInt8))
	}

	return 0
}

func (r *userRepository) optionalBool(v interface{}) bool {
	if v == nil {
		return false
	}
	return pgutils.BoolTo(v.(pgtype.Bool))
}
