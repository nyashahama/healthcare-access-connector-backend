package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
)

// AuthService handles auth operations
type AuthService interface {
	Register(ctx context.Context, email, phone, password, role string) (core.User, error)
	Login(ctx context.Context, identifier, password, ipAddress, userAgent string) (string, time.Time, core.User, error)
	Logout(ctx context.Context, tokenString string, userID uuid.UUID) error
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, tokenString string, ipAddress, userAgent string) (string, time.Time, core.User, error)
	VerifyEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, identifier string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ResendVerificationEmail(ctx context.Context, email string) error
}

// UserService handles user operations
type UserService interface {
	GetProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (core.User, error)
	UpdateProfile(ctx context.Context, userID uuid.UUID, updates map[string]interface{}) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	DeleteProfile(ctx context.Context, userID uuid.UUID) error
	ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, userID uuid.UUID, consent core.PrivacyConsent) error
	// Add new methods based on repository updates
	UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error
	UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error
	UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error
	UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error
	BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error
	GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error)
	SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error)
	CountUsers(ctx context.Context, role string) (int64, error)
	GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error)
}

// OTPService handles otp operations
type OTPService interface {
	GenerateOTP(ctx context.Context, identifier string) error
	VerifyOTP(ctx context.Context, identifier, otp string) (string, core.User, error)
	ResetPasswordWithOTP(ctx context.Context, identifier, otp, newPassword string) error
	// Add new methods based on repository updates
	GetLatestActiveOTP(ctx context.Context, userID uuid.UUID, otpType string) (core.OTPVerification, error)
	InvalidateUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error
	DeleteExpiredOTPs(ctx context.Context) error
	GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error)
	GetRecentOTPs(ctx context.Context, userID uuid.UUID, within time.Duration) ([]core.OTPVerification, error)
}

// SessionService defines the interface for session management operations
type SessionService interface {
	CreateSession(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time, ipAddress, userAgent, deviceType string) (core.UserSession, error)
	GetSession(ctx context.Context, token string) (core.UserSession, error)
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]core.UserSession, error)
	RevokeSession(ctx context.Context, token string, userID uuid.UUID) error
	RevokeAllSessions(ctx context.Context, userID uuid.UUID) error
	RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID uuid.UUID) error
	InvalidateSessionByDevice(ctx context.Context, userID uuid.UUID, deviceID string) error
	UpdateSessionToken(ctx context.Context, sessionID uuid.UUID, newToken string, expiresAt time.Time) error
	CleanupExpiredSessions(ctx context.Context) error
	GetActiveSessionCount(ctx context.Context, userID uuid.UUID) (int, error)
	ValidateAndExtendSession(ctx context.Context, token string, extendDuration time.Duration) (core.UserSession, error)
	StartSessionCleanupJob(interval time.Duration)
}

// NotificationService defines the interface for notification management operations
type NotificationService interface {
	GetPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error)
	UpdatePreferences(ctx context.Context, prefs core.NotificationPreferences) error
	CreatePreferences(ctx context.Context, prefs core.NotificationPreferences) (core.NotificationPreferences, error)
	DeletePreferences(ctx context.Context, userID uuid.UUID) error
	UpdateChannelSettings(ctx context.Context, userID uuid.UUID, sms, email, push bool) error
	UpdateAppointmentReminders(ctx context.Context, userID uuid.UUID, enabled bool, hoursBefore int) error
	UpdateHealthTips(ctx context.Context, userID uuid.UUID, enabled bool, frequency string) error
	UpdateMedicationReminders(ctx context.Context, userID uuid.UUID, enabled bool) error
	UpdateEmergencyAlerts(ctx context.Context, userID uuid.UUID, enabled bool) error
	SetQuietHours(ctx context.Context, userID uuid.UUID, startTime, endTime *time.Time) error
	UpdateNotificationLanguage(ctx context.Context, userID uuid.UUID, language string) error
	GetUsersWithDisabledNotifications(ctx context.Context, notificationType string) ([]uuid.UUID, error)
	GetUsersForHealthTips(ctx context.Context, frequency string) ([]uuid.UUID, error)
	CanSendNotification(ctx context.Context, userID uuid.UUID, notificationType, channel string) (bool, error)
}

// AuditService defines the interface for audit logging and reporting operations
type AuditService interface {
	LogUserActivity(ctx context.Context, activity core.UserActivity) error
	GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error)
	GetActivitiesByType(ctx context.Context, activityType string, startDate, endDate time.Time) ([]core.UserActivity, error)
	GetActivitiesByResource(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error)
	LogDataAccess(ctx context.Context, access core.DataAccessLog) error
	GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
	GetDataAccessLogsByAccessor(ctx context.Context, accessedByUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
	GetEmergencyAccessLogs(ctx context.Context, limit, offset int) ([]core.DataAccessLog, error)
	GetAccessLogsByResourceType(ctx context.Context, resourceType string, startDate, endDate time.Time) ([]core.DataAccessLog, error)
	GetSuspiciousActivities(ctx context.Context, threshold int) ([]core.UserActivity, error)
	GetFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, within time.Duration) ([]core.UserActivity, error)
	GetUnauthorizedAccessAttempts(ctx context.Context, within time.Duration) ([]core.DataAccessLog, error)
	ArchiveOldLogs(ctx context.Context, olderThan time.Duration) error
	DeleteArchivedLogs(ctx context.Context, olderThan time.Duration) error
	ArchiveOldActivities(ctx context.Context, olderThan time.Duration) error
	GenerateAccessReport(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (interface{}, error)
	GenerateActivityReport(ctx context.Context, startDate, endDate time.Time) (interface{}, error)
	ExportUserAuditTrail(ctx context.Context, userID uuid.UUID) ([]byte, error)
	StartCleanupJob(archiveInterval, deleteInterval time.Duration)
}

// ConsentService defines the interface for consent management operations
type ConsentService interface {
	GetPrivacyConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	CreatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error)
	UpdatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error
	UpdateHealthDataConsent(ctx context.Context, userID uuid.UUID, consent bool, version string) error
	UpdateResearchConsent(ctx context.Context, userID uuid.UUID, consent bool) error
	UpdateEmergencyAccessConsent(ctx context.Context, userID uuid.UUID, consent bool) error
	UpdateCommunicationConsents(ctx context.Context, userID uuid.UUID, sms, email bool) error
	UpdateDataSharingConsent(ctx context.Context, userID uuid.UUID, sharingPrefs map[string]interface{}) error
	GetConsentHistory(ctx context.Context, userID uuid.UUID) ([]core.PrivacyConsent, error)
	GetActiveConsentsByType(ctx context.Context, consentType string) ([]core.PrivacyConsent, error)
	GetExpiredConsents(ctx context.Context) ([]core.PrivacyConsent, error)
	GetWithdrawnConsents(ctx context.Context, startDate, endDate time.Time) ([]core.PrivacyConsent, error)
	ExportConsentData(ctx context.Context, userID uuid.UUID) ([]byte, error)
	NotifyConsentExpirations(ctx context.Context, daysBefore int) ([]uuid.UUID, error)
	StartConsentExpirationJob(interval time.Duration, notifyDaysBefore int)
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
