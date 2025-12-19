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

	// Convert email pointer to string for sqlc
	var email string
	if user.Email != nil {
		email = *user.Email
	}

	// Convert phone pointer to pgtype.Text for sqlc
	var phone pgtype.Text
	if user.Phone != nil {
		phone = pgtype.Text{String: *user.Phone, Valid: true}
	}

	created, err := r.db.CreateUser(ctx, sqlc.CreateUserParams{
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
		dbQueryTotal.WithLabelValues("create_user", "error").Inc()
		return domain.User{}, r.handleError(err, "create user")
	}

	dbQueryTotal.WithLabelValues("create_user", "success").Inc()

	return r.mapToUserFromCreate(created), nil
}

// GetUserByVerificationToken gets user by verification token
func (r *userRepository) GetUserByVerificationToken(ctx context.Context, token string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByVerificationToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_verification_token", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_verification_token", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by verification token")
	}

	dbQueryTotal.WithLabelValues("get_user_by_verification_token", "success").Inc()

	// Extract password hash
	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByVerificationToken(u), passwordHash, nil
}

// GetUserByPasswordResetToken gets user by password reset token
func (r *userRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByPasswordResetToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_password_reset_token", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_password_reset_token", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by password reset token")
	}

	dbQueryTotal.WithLabelValues("get_user_by_password_reset_token", "success").Inc()

	// Extract password hash
	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByPasswordResetToken(u), passwordHash, nil
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

	// Extract password hash
	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return r.mapToUserFromGetByEmail(u), passwordHash, nil
}

func (r *userRepository) GetUserByPhone(ctx context.Context, phone string) (domain.User, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByPhone(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_phone", "not_found").Inc()
			return domain.User{}, domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_phone", "error").Inc()
		return domain.User{}, r.handleError(err, "get user by phone")
	}

	dbQueryTotal.WithLabelValues("get_user_by_phone", "success").Inc()

	return r.mapToUserFromGetByPhone(u), nil
}

func (r *userRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (domain.User, string, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// For now, as a workaround, you can:
	u, err := r.db.GetUserByPhone(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "not_found").Inc()
			return domain.User{}, "", domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "error").Inc()
		return domain.User{}, "", r.handleError(err, "get user by phone with hash")
	}

	dbQueryTotal.WithLabelValues("get_user_by_phone_with_hash", "success").Inc()

	// Extract password hash - This is the issue! GetUserByPhone doesn't return password_hash
	// You need to modify the SQL query to include password_hash

	// Temporary workaround: get by email if available
	passwordHash := ""
	if u.Email != "" {
		userByEmail, hash, err := r.GetUserByEmail(ctx, u.Email)
		fmt.Println(userByEmail)
		if err == nil {
			passwordHash = hash
		}
	}

	return r.mapToUserFromGetByPhone(u), passwordHash, nil
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

// Helper functions for mapping

func (r *userRepository) mapToUserFromCreate(u sqlc.CreateUserRow) domain.User {
	return domain.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      false, // Not returned in CreateUser
		POPIAConsentGiven:    false, // Not returned in CreateUser
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *userRepository) mapToUserFromGetByEmail(u sqlc.GetUserByEmailRow) domain.User {
	return domain.User{
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

func (r *userRepository) mapToUserFromGetByPhone(u sqlc.GetUserByPhoneRow) domain.User {
	return domain.User{
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

func (r *userRepository) mapToUserFromGetByID(u sqlc.GetUserByIDRow) domain.User {
	return domain.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *userRepository) mapToUserFromList(u sqlc.ListUsersByRoleRow) domain.User {
	return domain.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
	}
}

func (r *userRepository) mapToUserFromGetByVerificationToken(u sqlc.GetUserByVerificationTokenRow) domain.User {
	return domain.User{
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

func (r *userRepository) mapToUserFromGetByPasswordResetToken(u sqlc.GetUserByPasswordResetTokenRow) domain.User {
	return domain.User{
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
// Utility functions for conversions
// ========================================

// String conversions (for VARCHAR that sqlc maps to string)
func stringToStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// pgtype.Text conversions
func pgtypeTextToString(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

func pgtypeTextToStringPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}

func stringToPgtypeText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: s, Valid: true}
}

func stringPtrToPgtypeText(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// UUID conversions (pgtype.UUID <-> uuid.UUID)
func pgtypeUUIDToUUID(u pgtype.UUID) uuid.UUID {
	return uuid.UUID(u.Bytes)
}

func uuidToPgtypeUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(u), Valid: true}
}

func pgtypeUUIDToUUIDPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	uid := uuid.UUID(u.Bytes)
	return &uid
}

func uuidPtrToPgtypeUUID(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: [16]byte(*u), Valid: true}
}

// Bool conversions
func pgtypeBoolToBool(b pgtype.Bool) bool {
	if !b.Valid {
		return false
	}
	return b.Bool
}

func boolToPgtypeBool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

func boolPtrToPgtypeBool(b *bool) pgtype.Bool {
	if b == nil {
		return pgtype.Bool{Valid: false}
	}
	return pgtype.Bool{Bool: *b, Valid: true}
}

// Timestamp conversions
func pgtypeTimestampToTimePtr(t pgtype.Timestamp) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func timeToPgtypeTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}

func timePtrToPgtypeTimestamp(t *time.Time) pgtype.Timestamp {
	if t == nil {
		return pgtype.Timestamp{Valid: false}
	}
	return pgtype.Timestamp{Time: *t, Valid: true}
}

// Int4 conversions
func pgtypeInt4ToInt32(i pgtype.Int4) int32 {
	if !i.Valid {
		return 0
	}
	return i.Int32
}

func int32ToPgtypeInt4(i int32) pgtype.Int4 {
	return pgtype.Int4{Int32: i, Valid: true}
}

func int32PtrToPgtypeInt4(i *int32) pgtype.Int4 {
	if i == nil {
		return pgtype.Int4{Valid: false}
	}
	return pgtype.Int4{Int32: *i, Valid: true}
}

// Int8 conversions
func pgtypeInt8ToInt64(i pgtype.Int8) int64 {
	if !i.Valid {
		return 0
	}
	return i.Int64
}

func int64ToPgtypeInt8(i int64) pgtype.Int8 {
	return pgtype.Int8{Int64: i, Valid: true}
}

// Float8 conversions
func pgtypeFloat8ToFloat64(f pgtype.Float8) float64 {
	if !f.Valid {
		return 0
	}
	return f.Float64
}

func float64ToPgtypeFloat8(f float64) pgtype.Float8 {
	return pgtype.Float8{Float64: f, Valid: true}
}

func float64PtrToPgtypeFloat8(f *float64) pgtype.Float8 {
	if f == nil {
		return pgtype.Float8{Valid: false}
	}
	return pgtype.Float8{Float64: *f, Valid: true}
}
