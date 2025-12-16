// Package repository implements data access layer
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository/sqlc"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
		Username:     user.Username,
		Email:        user.Email,
		PasswordHash: passwordHash,
		Role:         user.Role,
	})
	if err != nil {
		dbQueryTotal.WithLabelValues("create_user", "error").Inc()
		return domain.User{}, r.handleError(err, "create user")
	}

	dbQueryTotal.WithLabelValues("create_user", "success").Inc()

	return domain.User{
		ID:        created.ID,
		Username:  created.Username,
		Email:     created.Email,
		Role:      created.Role,
		CreatedAt: created.CreatedAt,
	}, nil
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

	return domain.User{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}, u.PasswordHash, nil
}

func (r *userRepository) GetUserByID(ctx context.Context, id int32) (domain.User, error) {
	start := time.Now()
	defer func() {
		dbQueryDuration.Observe(time.Since(start).Seconds())
	}()

	u, err := r.db.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			dbQueryTotal.WithLabelValues("get_user_by_id", "not_found").Inc()
			return domain.User{}, domain.ErrUserNotFound
		}
		dbQueryTotal.WithLabelValues("get_user_by_id", "error").Inc()
		return domain.User{}, r.handleError(err, "get user by id")
	}

	dbQueryTotal.WithLabelValues("get_user_by_id", "success").Inc()

	return domain.User{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}, nil
}

func (r *userRepository) GetUserByUsername(ctx context.Context, username string) (domain.User, error) {
	// Implementation placeholder - add to sqlc queries
	return domain.User{}, fmt.Errorf("not implemented")
}

func (r *userRepository) UpdateUser(ctx context.Context, user domain.User) error {
	// Implementation placeholder - add to sqlc queries
	return fmt.Errorf("not implemented")
}

func (r *userRepository) DeleteUser(ctx context.Context, id int32) error {
	// Implementation placeholder - add to sqlc queries
	return fmt.Errorf("not implemented")
}

func (r *userRepository) ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error) {
	// Implementation placeholder - add to sqlc queries
	return nil, fmt.Errorf("not implemented")
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
			if strings.Contains(pgErr.ConstraintName, "username") {
				return domain.ErrDuplicateUsername
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
