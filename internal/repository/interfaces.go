// Package repository defines repository interfaces
package repository

import (
	"context"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"

	"github.com/jackc/pgx/v5"
)

// UserRepository defines methods for user data access
type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User, passwordHash string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, string, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	GetUserByPhone(ctx context.Context, phone string) (domain.User, error)
	UpdateUser(ctx context.Context, user domain.User) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	VerifyUser(ctx context.Context, id uuid.UUID) error
	DeactivateUser(ctx context.Context, id uuid.UUID) error
	ListUsers(ctx context.Context, role string, limit, offset int) ([]domain.User, error)
	CountUsers(ctx context.Context, role string) (int64, error)
}

// TxManager handles database transactions
type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
}
