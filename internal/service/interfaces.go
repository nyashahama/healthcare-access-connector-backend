// Package service defines service interfaces
package service

import (
	"context"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
)

// AuthService handles authentication operations
type AuthService interface {
	// Registration
	RegisterWithEmail(ctx context.Context, email, password, role string) (domain.User, error)
	RegisterWithPhone(ctx context.Context, phone, password, role string) (domain.User, error)
	RegisterSMSOnly(ctx context.Context, phone, role string) (domain.User, error)

	// Login
	LoginWithEmail(ctx context.Context, email, password string) (string, time.Time, error)
	LoginWithPhone(ctx context.Context, phone, password string) (string, time.Time, error)

	// Token management
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, token string) (string, time.Time, error)

	// Verification
	SendVerificationEmail(ctx context.Context, userID uuid.UUID) error
	SendVerificationSMS(ctx context.Context, userID uuid.UUID) error
	VerifyEmail(ctx context.Context, token string) error
	VerifyPhone(ctx context.Context, token string) error

	// Password reset
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error

	// Session management
	Logout(ctx context.Context, sessionToken string) error
	LogoutAllSessions(ctx context.Context, userID uuid.UUID) error
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
