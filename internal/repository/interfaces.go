// Package repository defines repository interfaces
package repository

import (
	"context"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"

	"github.com/jackc/pgx/v5"
)

// UserRepository defines methods for user data access
type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User, passwordHash string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, string, error)
	GetUserByID(ctx context.Context, id int32) (domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (domain.User, error)
	UpdateUser(ctx context.Context, user domain.User) error
	DeleteUser(ctx context.Context, id int32) error
	ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error)
}

// TxManager handles database transactions
type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
}
