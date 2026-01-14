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
	userDbQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "user_db_query_duration_seconds",
			Help:    "User database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	userDbQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "user_db_query_total",
			Help: "Total number of user database queries",
		},
		[]string{"operation", "status"},
	)
)

type userRepository struct {
	querier sqlc.Querier
}

// NewUserRepository creates a new user repository using a pool
func NewUserRepository(pool *pgxpool.Pool) repository.UserRepository {
	return NewUserRepositoryWithQuerier(sqlc.New(pool))
}

// NewUserRepositoryWithQuerier creates a new user repository using a provided querier (for transactions)
func NewUserRepositoryWithQuerier(querier sqlc.Querier) repository.UserRepository {
	return &userRepository{
		querier: querier,
	}
}

func (r *userRepository) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	start := time.Now()
	defer func() {
		userDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgID := uuidToPgtypeUUID(id)
	u, err := r.querier.GetUserByID(ctx, pgID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			userDbQueryTotal.WithLabelValues("get_user_by_id", "not_found").Inc()
			return core.User{}, domain.ErrUserNotFound
		}
		userDbQueryTotal.WithLabelValues("get_user_by_id", "error").Inc()
		return core.User{}, fmt.Errorf("get user by id: %w", err)
	}

	userDbQueryTotal.WithLabelValues("get_user_by_id", "success").Inc()
	return r.mapToUserFromGetByID(u), nil
}

func (r *userRepository) UpdateUser(ctx context.Context, user core.User) error {
	start := time.Now()
	defer func() {
		userDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// TODO: Implement specific update queries
	userDbQueryTotal.WithLabelValues("update_user", "error").Inc()
	return fmt.Errorf("not implemented")
}

func (r *userRepository) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		userDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: "inactive", Valid: true},
	})
	if err != nil {
		userDbQueryTotal.WithLabelValues("deactivate_user", "error").Inc()
		return fmt.Errorf("deactivate user: %w", err)
	}

	userDbQueryTotal.WithLabelValues("deactivate_user", "success").Inc()
	return nil
}

func (r *userRepository) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	start := time.Now()
	defer func() {
		userDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	users, err := r.querier.ListUsersByRole(ctx, sqlc.ListUsersByRoleParams{
		Role:   role,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		userDbQueryTotal.WithLabelValues("list_users", "error").Inc()
		return nil, fmt.Errorf("list users: %w", err)
	}

	userDbQueryTotal.WithLabelValues("list_users", "success").Inc()

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = r.mapToUserFromList(u)
	}

	return result, nil
}

func (r *userRepository) CountUsers(ctx context.Context, role string) (int64, error) {
	start := time.Now()
	defer func() {
		userDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.querier.CountUsersByRole(ctx, role)
	if err != nil {
		userDbQueryTotal.WithLabelValues("count_users", "error").Inc()
		return 0, fmt.Errorf("count users: %w", err)
	}

	userDbQueryTotal.WithLabelValues("count_users", "success").Inc()
	return count, nil
}

func (r *userRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		userDbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// TODO: Implement this query to get user with patient profile
	// For now, return empty patient profile
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		userDbQueryTotal.WithLabelValues("get_user_profile", "error").Inc()
		return core.User{}, patients.PatientProfile{}, err
	}

	userDbQueryTotal.WithLabelValues("get_user_profile", "success").Inc()
	return user, patients.PatientProfile{}, nil
}

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
