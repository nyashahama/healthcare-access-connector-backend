// Package service defines service interfaces
package service

import (
	"context"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
)

// AuthService handles authentication operations
type AuthService interface {
	Register(ctx context.Context, username, email, password, role string) (domain.User, error)
	Login(ctx context.Context, email, password string) (string, time.Time, error)
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, token string) (string, time.Time, error)
}

// UserService handles user operations
type UserService interface {
	GetProfile(ctx context.Context, userID int32) (domain.User, error)
	GetUserByID(ctx context.Context, userID int32) (domain.User, error)
	UpdateProfile(ctx context.Context, userID int32, updates map[string]interface{}) error
	DeleteProfile(ctx context.Context, userID int32) error
	ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error)
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID int32  `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}