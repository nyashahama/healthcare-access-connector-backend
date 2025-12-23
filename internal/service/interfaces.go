// Package service defines service interfaces for health project
package service

import (
	"context"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
)

// AuthService handles authentication operations for health project
type AuthService interface {
	Register(ctx context.Context, email, phone, password, role string) (domain.User, error)
	Login(ctx context.Context, identifier, password string) (string, time.Time, domain.User, error)
	Logout(ctx context.Context, tokenString string, userID uuid.UUID) error
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, tokenString string) (string, time.Time, domain.User, error)
	RequestPasswordReset(ctx context.Context, identifier string) error
	VerifyEmail(ctx context.Context, token string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ResendVerificationEmail(ctx context.Context, email string) error
	GenerateOTP(ctx context.Context, identifier string) error
	VerifyOTP(ctx context.Context, identifier, otp string) (string, error) // Returns reset token
	RequestPasswordResetWithOTP(ctx context.Context, identifier string) error
}

// UserService handles user operations for health project
type UserService interface {
	GetProfile(ctx context.Context, userID uuid.UUID) (domain.User, domain.PatientProfile, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (domain.User, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	DeleteProfile(ctx context.Context, userID uuid.UUID) error
	ListUsers(ctx context.Context, role string, limit, offset int) ([]domain.User, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (domain.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, userID uuid.UUID, consent domain.PrivacyConsent) error
}

// PatientService handles patient operations
type PatientService interface {
	CreateMedicalInfo(ctx context.Context, patientID uuid.UUID, info domain.PatientMedicalInfo) error
	GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (domain.PatientMedicalInfo, error)
	AddAllergy(ctx context.Context, allergy domain.PatientAllergy) error
	GetAllergies(ctx context.Context, patientID uuid.UUID) ([]domain.PatientAllergy, error)
	AddMedication(ctx context.Context, medication domain.PatientMedication) error
	GetMedications(ctx context.Context, patientID uuid.UUID) ([]domain.PatientMedication, error)
	AddCondition(ctx context.Context, condition domain.PatientCondition) error
	GetConditions(ctx context.Context, patientID uuid.UUID) ([]domain.PatientCondition, error)
	AddImmunization(ctx context.Context, immunization domain.PatientImmunization) error
	GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]domain.PatientImmunization, error)
}

// TokenClaims represents JWT token claims for health project
type TokenClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	Email  string    `json:"email"`
}
