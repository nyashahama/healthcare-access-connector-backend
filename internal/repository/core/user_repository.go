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
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	userDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "user_db_query_duration_seconds",
			Help:    "User database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	userDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "user_db_query_total",
			Help: "Total number of user database queries",
		},
		[]string{"operation", "status"},
	)
)

type userRepository struct {
	querier            sqlc.Querier
	patientProfileRepo repository.PatientProfileRepository
}

// NewUserRepository creates a new user repository using a pool
func NewUserRepository(pool *pgxpool.Pool, patientProfileRepo repository.PatientProfileRepository) repository.UserRepository {
	return NewUserRepositoryWithQuerier(sqlc.New(pool), patientProfileRepo)
}

// NewUserRepositoryWithQuerier creates a new user repository using a provided querier (for transactions)
func NewUserRepositoryWithQuerier(querier sqlc.Querier, patientProfileRepo repository.PatientProfileRepository) repository.UserRepository {
	return &userRepository{
		querier:            querier,
		patientProfileRepo: patientProfileRepo,
	}
}

func (r *userRepository) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgID := uuidToPgtypeUUID(id)
	u, err := r.querier.GetUserByID(ctx, pgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			userDBQueryTotal.WithLabelValues("get_user_by_id", "not_found").Inc()
			return core.User{}, domain.ErrUserNotFound
		}
		userDBQueryTotal.WithLabelValues("get_user_by_id", "error").Inc()
		return core.User{}, fmt.Errorf("get user by id: %w", err)
	}

	userDBQueryTotal.WithLabelValues("get_user_by_id", "success").Inc()
	return r.mapToUserFromGetByID(u), nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user core.User) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var email string
	if user.Email != nil {
		email = *user.Email
	}

	var phone pgtype.Text
	if user.Phone != nil {
		phone = pgtype.Text{String: *user.Phone, Valid: true}
	}

	err := r.querier.UpdateUser(ctx, sqlc.UpdateUserParams{
		ID:                          uuidToPgtypeUUID(user.ID),
		Email:                       email,
		Phone:                       phone,
		Role:                        user.Role,
		Status:                      pgtype.Text{String: user.Status, Valid: true},
		IsSmsOnly:                   pgtype.Bool{Bool: user.IsSMSOnly, Valid: true},
		SmsConsentGiven:             pgtype.Bool{Bool: user.SMSConsentGiven, Valid: true},
		PopiaConsentGiven:           pgtype.Bool{Bool: user.POPIAConsentGiven, Valid: true},
		ConsentDate:                 timePtrToPgtypeTimestamp(user.ConsentDate),
		ProfileCompletionPercentage: pgtype.Int4{Int32: int32(user.ProfileCompletionPct), Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user", "error").Inc()
		return fmt.Errorf("update user: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user", "success").Inc()
	return nil
}

func (r *userRepository) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: "inactive", Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("deactivate_user", "error").Inc()
		return fmt.Errorf("deactivate user: %w", err)
	}

	userDBQueryTotal.WithLabelValues("deactivate_user", "success").Inc()
	return nil
}

func (r *userRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteUser(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		userDBQueryTotal.WithLabelValues("delete_user", "error").Inc()
		return fmt.Errorf("delete user: %w", err)
	}

	userDBQueryTotal.WithLabelValues("delete_user", "success").Inc()
	return nil
}

func (r *userRepository) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	users, err := r.querier.ListUsersByRole(ctx, sqlc.ListUsersByRoleParams{
		Role:   role,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("list_users", "error").Inc()
		return nil, fmt.Errorf("list users: %w", err)
	}

	userDBQueryTotal.WithLabelValues("list_users", "success").Inc()

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = r.mapToUserFromList(u)
	}

	return result, nil
}

func (r *userRepository) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	users, err := r.querier.SearchUsers(ctx, sqlc.SearchUsersParams{
		Column1: query,
		Column2: role,
		Column3: status,
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("search_users", "error").Inc()
		return nil, fmt.Errorf("search users: %w", err)
	}

	userDBQueryTotal.WithLabelValues("search_users", "success").Inc()

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = r.mapToUserFromSearch(u)
	}

	return result, nil
}

func (r *userRepository) CountUsers(ctx context.Context, role string) (int64, error) {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.querier.CountUsersByRole(ctx, role)
	if err != nil {
		userDBQueryTotal.WithLabelValues("count_users", "error").Inc()
		return 0, fmt.Errorf("count users: %w", err)
	}

	userDBQueryTotal.WithLabelValues("count_users", "success").Inc()
	return count, nil
}

func (r *userRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get the user
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		userDBQueryTotal.WithLabelValues("get_user_profile", "error").Inc()
		return core.User{}, patients.PatientProfile{}, err
	}

	// Get patient profile using the injected patient profile repository
	patientProfile, err := r.patientProfileRepo.GetPatientProfileByUserID(ctx, userID)
	if err != nil {
		// Check if error is "not found" - that's acceptable for users who aren't patients
		if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrPatientNotFound) {
			// Return user with empty patient profile
			userDBQueryTotal.WithLabelValues("get_user_profile", "success").Inc()
			return user, patients.PatientProfile{}, nil
		}
		userDBQueryTotal.WithLabelValues("get_user_profile", "error").Inc()
		return core.User{}, patients.PatientProfile{}, fmt.Errorf("get patient profile: %w", err)
	}

	userDBQueryTotal.WithLabelValues("get_user_profile", "success").Inc()
	return user, patientProfile, nil
}

func (r *userRepository) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserEmail(ctx, sqlc.UpdateUserEmailParams{
		ID:    uuidToPgtypeUUID(id),
		Email: email,
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user_email", "error").Inc()
		return fmt.Errorf("update user email: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user_email", "success").Inc()
	return nil
}

func (r *userRepository) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserPhone(ctx, sqlc.UpdateUserPhoneParams{
		ID:    uuidToPgtypeUUID(id),
		Phone: pgtype.Text{String: phone, Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user_phone", "error").Inc()
		return fmt.Errorf("update user phone: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user_phone", "success").Inc()
	return nil
}

func (r *userRepository) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserRole(ctx, sqlc.UpdateUserRoleParams{
		ID:   uuidToPgtypeUUID(id),
		Role: role,
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user_role", "error").Inc()
		return fmt.Errorf("update user role: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user_role", "success").Inc()
	return nil
}

func (r *userRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user_status", "error").Inc()
		return fmt.Errorf("update user status: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user_status", "success").Inc()
	return nil
}

func (r *userRepository) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserProfileCompletion(ctx, sqlc.UpdateUserProfileCompletionParams{
		ID:                          uuidToPgtypeUUID(id),
		ProfileCompletionPercentage: pgtype.Int4{Int32: int32(percentage), Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user_profile_completion", "error").Inc()
		return fmt.Errorf("update user profile completion: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user_profile_completion", "success").Inc()
	return nil
}

func (r *userRepository) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserConsents(ctx, sqlc.UpdateUserConsentsParams{
		ID:                uuidToPgtypeUUID(id),
		SmsConsentGiven:   pgtype.Bool{Bool: smsConsent, Valid: true},
		PopiaConsentGiven: pgtype.Bool{Bool: popiaConsent, Valid: true},
		ConsentDate:       pgtype.Timestamp{Time: consentDate, Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("update_user_consents", "error").Inc()
		return fmt.Errorf("update user consents: %w", err)
	}

	userDBQueryTotal.WithLabelValues("update_user_consents", "success").Inc()
	return nil
}

func (r *userRepository) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkUpdateUserStatus(ctx, sqlc.BulkUpdateUserStatusParams{
		Column1: pgIDs,
		Status:  pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		userDBQueryTotal.WithLabelValues("bulk_update_status", "error").Inc()
		return fmt.Errorf("bulk update status: %w", err)
	}

	userDBQueryTotal.WithLabelValues("bulk_update_status", "success").Inc()
	return nil
}

func (r *userRepository) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	start := time.Now()
	defer func() {
		userDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgIDs[i] = uuidToPgtypeUUID(id)
	}

	users, err := r.querier.GetUsersByIDs(ctx, pgIDs)
	if err != nil {
		userDBQueryTotal.WithLabelValues("get_users_by_ids", "error").Inc()
		return nil, fmt.Errorf("get users by ids: %w", err)
	}

	userDBQueryTotal.WithLabelValues("get_users_by_ids", "success").Inc()

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = r.mapToUserFromGetByIDs(u)
	}

	return result, nil
}

// Mapping functions
func (r *userRepository) mapToUserFromGetByID(u sqlc.GetUserByIDRow) core.User {
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
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func (r *userRepository) mapToUserFromList(u sqlc.ListUsersByRoleRow) core.User {
	return core.User{
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

func (r *userRepository) mapToUserFromSearch(u sqlc.SearchUsersRow) core.User {
	return core.User{
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

func (r *userRepository) mapToUserFromGetByIDs(u sqlc.GetUsersByIDsRow) core.User {
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
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}
