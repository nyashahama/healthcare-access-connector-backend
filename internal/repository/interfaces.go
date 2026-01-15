package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"

	"github.com/jackc/pgx/v5"
)

// AuthRepository defines methods for authentication
type AuthRepository interface {
	// User Authentication
	CreateUser(ctx context.Context, user core.User, passwordHash string) (core.User, error)
	GetUserByEmail(ctx context.Context, email string) (core.User, string, error)
	GetUserByPhone(ctx context.Context, phone string) (core.User, error)
	GetUserByPhoneWithHash(ctx context.Context, phone string) (core.User, string, error)

	// Token Management
	GetUserByVerificationToken(ctx context.Context, token string) (core.User, string, error)
	GetUserByPasswordResetToken(ctx context.Context, token string) (core.User, string, error)
	SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error
	SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error
	VerifyUser(ctx context.Context, id uuid.UUID) error

	// Password Management
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error

	// Session & Status
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
}

// UserRepository defines methods for user
type UserRepository interface {
	// Basic CRUD
	GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error)
	UpdateUser(ctx context.Context, user core.User) error
	DeactivateUser(ctx context.Context, id uuid.UUID) error

	// Listing & Search
	ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error)
	CountUsers(ctx context.Context, role string) (int64, error)

	// Profile Management
	GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error)
	// Specific updates (optional - for more granular control)
	UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error
	UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error
	UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error
	UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error
}

// OTPRepository defines methods for otp
type OTPRepository interface {
	// OTP Operations
	SaveOTP(ctx context.Context, otp core.OTPVerification) error
	GetOTP(ctx context.Context, userID uuid.UUID, otp, otpType string) (core.OTPVerification, error)
	MarkOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error
	DeleteExpiredOTPs(ctx context.Context) error
	DeleteUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error
	GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error)
}

// PatientRepository defines methods for patient profile data access
type PatientRepository interface {
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	SearchPatients(ctx context.Context, query string, province string, limit, offset int) ([]patients.PatientProfile, error)

	// Medical Information
	CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error
	GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error)
	UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error

	// Allergies
	AddAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error)
	GetAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	UpdateAllergy(ctx context.Context, allergy patients.PatientAllergy) error
	DeleteAllergy(ctx context.Context, id uuid.UUID) error

	// Medications
	AddMedication(ctx context.Context, med patients.PatientMedication) (patients.PatientMedication, error)
	GetMedications(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientMedication, error)
	UpdateMedication(ctx context.Context, med patients.PatientMedication) error

	// Conditions
	AddCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error)
	GetConditions(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientCondition, error)
	UpdateCondition(ctx context.Context, condition patients.PatientCondition) error

	// Immunizations
	AddImmunization(ctx context.Context, imm patients.PatientImmunization) (patients.PatientImmunization, error)
	GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
}

// ClinicRepository defines methods for clinic data access
type ClinicRepository interface {
	CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	VerifyClinic(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error
	ListClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error)
	SearchClinics(ctx context.Context, query string, province string, city string, limit, offset int) ([]providers.Clinic, error)
	SearchClinicsByLocation(ctx context.Context, lat, lng float64, radiusKm float64) ([]providers.Clinic, error)

	// Clinic Services
	AddClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error)
	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	UpdateClinicService(ctx context.Context, service providers.ClinicService) error
	DeactivateClinicService(ctx context.Context, id uuid.UUID) error
}

// StaffRepository defines methods for clinic staff data access
type StaffRepository interface {
	CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error)
	GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error)
	GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error)
	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role string) ([]providers.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error
	UpdateStaffStatus(ctx context.Context, id uuid.UUID, status string) error

	// Credentials
	AddCredential(ctx context.Context, cred providers.ProfessionalCredential) (providers.ProfessionalCredential, error)
	GetCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	VerifyCredential(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID) error
	UpdateCredential(ctx context.Context, cred providers.ProfessionalCredential) error
}

// SessionRepository defines methods for session management
type SessionRepository interface {
	CreateSession(ctx context.Context, session core.UserSession) (core.UserSession, error)
	GetSession(ctx context.Context, sessionToken string) (core.UserSession, error)
	DeleteSession(ctx context.Context, sessionToken string) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context) error
}

// ConsentRepository defines methods for privacy consent management (POPIA compliance)
type ConsentRepository interface {
	CreateConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, consent core.PrivacyConsent) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error
}

// AuditRepository defines methods for audit logging (POPIA compliance)
type AuditRepository interface {
	LogActivity(ctx context.Context, activity core.UserActivity) error
	GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error)

	LogDataAccess(ctx context.Context, access core.DataAccessLog) error
	GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
}

// NotificationRepository defines methods for notification preferences
type NotificationRepository interface {
	CreatePreferences(ctx context.Context, prefs core.NotificationPreferences) (core.NotificationPreferences, error)
	GetPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error)
	UpdatePreferences(ctx context.Context, prefs core.NotificationPreferences) error
}

// SMSRepository defines methods for SMS conversation tracking
type SMSRepository interface {
	CreateConversation(ctx context.Context, conv sms.SMSConversation) (sms.SMSConversation, error)
	GetConversationByPhone(ctx context.Context, phone string) (sms.SMSConversation, error)
	UpdateConversation(ctx context.Context, conv sms.SMSConversation) error

	LogMessage(ctx context.Context, msg sms.SMSMessage) (sms.SMSMessage, error)
	GetConversationMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]sms.SMSMessage, error)
}

// TxManager handles database transactions
type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
}
