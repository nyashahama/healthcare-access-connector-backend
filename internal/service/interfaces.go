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
	GetProfile(ctx context.Context, userID uuid.UUID) (domain.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error)
	UpdateUserStatus(ctx context.Context, userID uuid.UUID, status string) error
	DeactivateUser(ctx context.Context, userID uuid.UUID) error
	ListUsers(ctx context.Context, role string, limit, offset int) ([]domain.User, error)
	CountUsers(ctx context.Context, role string) (int64, error)
}

// PatientService handles patient profile operations
type PatientService interface {
	CreateProfile(ctx context.Context, userID uuid.UUID, profile domain.PatientProfile) (domain.PatientProfile, error)
	GetProfile(ctx context.Context, userID uuid.UUID) (domain.PatientProfile, error)
	UpdateProfile(ctx context.Context, profile domain.PatientProfile) error
	SearchPatients(ctx context.Context, query string, province string, limit, offset int) ([]domain.PatientProfile, error)

	// Medical information
	UpdateMedicalInfo(ctx context.Context, info domain.PatientMedicalInfo) error
	GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (domain.PatientMedicalInfo, error)
}

// ConsentService handles POPIA consent operations
type ConsentService interface {
	CreateConsent(ctx context.Context, userID uuid.UUID, consent domain.PrivacyConsent) (domain.PrivacyConsent, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (domain.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, consent domain.PrivacyConsent) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error
	CheckHealthDataConsent(ctx context.Context, userID uuid.UUID) error
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID int32  `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}
