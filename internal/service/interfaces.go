package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// ===================== AUTH SERVICE =====================
type AuthService interface {
	Register(ctx context.Context, email, phone, password, role string) (core.User, error)
	Login(ctx context.Context, identifier, password string) (string, time.Time, core.User, error)
	Logout(ctx context.Context, tokenString string, userID uuid.UUID) error
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, tokenString string) (string, time.Time, core.User, error)
	VerifyEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, identifier string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ResendVerificationEmail(ctx context.Context, email string) error
}

// ===================== USER SERVICE =====================
type UserService interface {
	GetProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (core.User, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	DeleteProfile(ctx context.Context, userID uuid.UUID) error
	ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, userID uuid.UUID, consent core.PrivacyConsent) error
}

// ===================== OTP SERVICE =====================
type OTPService interface {
	GenerateOTP(ctx context.Context, identifier string) error
	VerifyOTP(ctx context.Context, identifier, otp string) (string, error)
	ResetPasswordWithOTP(ctx context.Context, identifier, otp, newPassword string) error
}


// PatientService handles patient operations
type PatientService interface {
	CreateMedicalInfo(ctx context.Context, patientID uuid.UUID, info patients.PatientMedicalInfo) error
	GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error)
	AddAllergy(ctx context.Context, allergy patients.PatientAllergy) error
	GetAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	AddMedication(ctx context.Context, medication patients.PatientMedication) error
	GetMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
	AddCondition(ctx context.Context, condition patients.PatientCondition) error
	GetConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
	AddImmunization(ctx context.Context, immunization patients.PatientImmunization) error
	GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
}

// ClinicService handles clinic operations
type ClinicService interface {
	CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	VerifyClinic(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error
	ListClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error)
	SearchClinics(ctx context.Context, query string, province string, city string, limit, offset int) ([]providers.Clinic, error)
	SearchClinicsByLocation(ctx context.Context, lat, lng float64, radiusKm float64) ([]providers.Clinic, error)
}

// TokenClaims represents JWT token claims for health project
type TokenClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	Email  string    `json:"email"`
}