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

// ============================================
// AUTHENTICATION & SESSION MANAGEMENT
// ============================================

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
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
}

// ============================================
// SESSION REPOSITORY
// Maps to: user_sessions.sql
// ============================================

type SessionRepository interface {
	// Core CRUD Operations
	CreateSession(ctx context.Context, session core.UserSession) (core.UserSession, error)
	GetSession(ctx context.Context, sessionToken string) (core.UserSession, error)
	DeleteSession(ctx context.Context, sessionToken string) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context) error
	UpdateSessionToken(ctx context.Context, id uuid.UUID, sessionToken string, expiresAt time.Time) error

	// Additional methods for complete session management
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]core.UserSession, error)
	RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID uuid.UUID) error
	InvalidateSessionByDevice(ctx context.Context, userID uuid.UUID, deviceID string) error
}

type OTPRepository interface {
	// OTP Operations
	SaveOTP(ctx context.Context, otp core.OTPVerification) error
	GetOTP(ctx context.Context, userID uuid.UUID, otp, otpType string) (core.OTPVerification, error)
	GetLatestActiveOTP(ctx context.Context, userID uuid.UUID, otpType string) (core.OTPVerification, error)
	MarkOTPUsed(ctx context.Context, otpID uuid.UUID, usedAt *time.Time) error
	InvalidateUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error
	DeleteExpiredOTPs(ctx context.Context) error
	DeleteUserOTPs(ctx context.Context, userID uuid.UUID, otpType string) error

	// Security & Rate Limiting
	GetOTPAttemptCount(ctx context.Context, userID uuid.UUID, otpType string) (int64, error)
	GetRecentOTPs(ctx context.Context, userID uuid.UUID, within time.Duration) ([]core.OTPVerification, error)
}

// ============================================
// USER MANAGEMENT & PROFILES
// ============================================

type UserRepository interface {
	// Basic CRUD
	GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error)
	UpdateUser(ctx context.Context, user core.User) error
	DeactivateUser(ctx context.Context, id uuid.UUID) error
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// Listing & Search
	ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error)
	SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error)
	CountUsers(ctx context.Context, role string) (int64, error)

	// Profile Management
	GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error)

	// Specific Updates
	UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error
	UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error
	UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error
	UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error

	// Bulk Operations
	BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error
	GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error)
}

// ============================================
// PRIVACY CONSENT REPOSITORY (POPIA Compliance)
// Maps to: privacy_consents.sql
// ============================================

type ConsentRepository interface {
	// Core CRUD Operations
	CreatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error)
	GetPrivacyConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	UpdatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error

	// Consent Type Updates
	UpdateHealthDataConsent(ctx context.Context, userID uuid.UUID, consent bool, version string) error
	UpdateResearchConsent(ctx context.Context, userID uuid.UUID, consent bool) error
	UpdateEmergencyAccessConsent(ctx context.Context, userID uuid.UUID, consent bool) error
	UpdateCommunicationConsents(ctx context.Context, userID uuid.UUID, sms, email bool) error
	UpdateDataSharingConsent(ctx context.Context, userID uuid.UUID, sharingPrefs map[string]interface{}) error

	// Compliance & Reporting
	GetConsentHistory(ctx context.Context, userID uuid.UUID) ([]core.PrivacyConsent, error)
	GetActiveConsentsByType(ctx context.Context, consentType string) ([]core.PrivacyConsent, error)
	GetExpiredConsents(ctx context.Context) ([]core.PrivacyConsent, error)
	GetWithdrawnConsents(ctx context.Context, startDate, endDate time.Time) ([]core.PrivacyConsent, error)

	// Export for POPIA data subject access requests
	ExportConsentData(ctx context.Context, userID uuid.UUID) ([]byte, error)
	NotifyConsentExpirations(ctx context.Context, daysBefore int) ([]uuid.UUID, error)
}

// ============================================
// AUDIT REPOSITORY (POPIA Compliance)
// Maps to: user_activities.sql & data_access_logs.sql
// ============================================

type AuditRepository interface {
	// User Activity Logging
	LogUserActivity(ctx context.Context, activity core.UserActivity) error
	GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error)
	GetActivitiesByType(ctx context.Context, activityType string, startDate, endDate time.Time) ([]core.UserActivity, error)
	GetActivitiesByResource(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error)

	// Data Access Logging (POPIA Requirement)
	LogDataAccess(ctx context.Context, access core.DataAccessLog) error
	GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
	GetDataAccessLogsByAccessor(ctx context.Context, accessedByUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
	GetEmergencyAccessLogs(ctx context.Context, limit, offset int) ([]core.DataAccessLog, error)
	GetAccessLogsByResourceType(ctx context.Context, resourceType string, startDate, endDate time.Time) ([]core.DataAccessLog, error)

	// Security Monitoring
	GetSuspiciousActivities(ctx context.Context, threshold int) ([]core.UserActivity, error)
	GetFailedLoginAttempts(ctx context.Context, userID *uuid.UUID, within time.Duration) ([]core.UserActivity, error)
	GetUnauthorizedAccessAttempts(ctx context.Context, within time.Duration) ([]core.DataAccessLog, error)

	// Retention & Cleanup
	ArchiveOldLogs(ctx context.Context, olderThan time.Duration) error
	DeleteArchivedLogs(ctx context.Context, olderThan time.Duration) error
	ArchiveOldActivities(ctx context.Context, olderThan time.Duration) error

	// Compliance Reporting
	GenerateAccessReport(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (interface{}, error)
	GenerateActivityReport(ctx context.Context, startDate, endDate time.Time) (interface{}, error)
	ExportUserAuditTrail(ctx context.Context, userID uuid.UUID) ([]byte, error)
}

// ============================================
// NOTIFICATION & COMMUNICATION
// ============================================

type NotificationRepository interface {
	// Core CRUD Operations
	CreateNotificationPreferences(ctx context.Context, prefs core.NotificationPreferences) (core.NotificationPreferences, error)
	GetNotificationPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error)
	UpdateNotificationPreferences(ctx context.Context, prefs core.NotificationPreferences) error
	DeleteNotificationPreferences(ctx context.Context, userID uuid.UUID) error

	// Channel-Specific Updates
	UpdateChannelSettings(ctx context.Context, userID uuid.UUID, sms, email, push bool) error
	UpdateAppointmentReminders(ctx context.Context, userID uuid.UUID, enabled bool, hoursBefore int) error
	UpdateHealthTips(ctx context.Context, userID uuid.UUID, enabled bool, frequency string) error
	UpdateMedicationReminders(ctx context.Context, userID uuid.UUID, enabled bool) error
	UpdateEmergencyAlerts(ctx context.Context, userID uuid.UUID, enabled bool) error

	// Quiet Hours Management
	SetQuietHours(ctx context.Context, userID uuid.UUID, startTime, endTime *time.Time) error
	UpdateNotificationLanguage(ctx context.Context, userID uuid.UUID, language string) error

	// Bulk Operations
	GetUsersWithDisabledNotifications(ctx context.Context, notificationType string) ([]uuid.UUID, error)
	GetUsersForHealthTips(ctx context.Context, frequency string) ([]uuid.UUID, error)
}

// ============================================
// PATIENT MANAGEMENT (Comprehensive)
// ============================================

// ============================================
// PATIENT PROFILE REPOSITORY
// Maps to: patient_profiles.sql
// ============================================

type PatientProfileRepository interface {
	// Core CRUD Operations
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	DeletePatientProfile(ctx context.Context, id uuid.UUID) error
	DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error

	// Profile Management
	// UpdatePatientPersonalInfo(ctx context.Context, userID uuid.UUID, firstName, lastName, preferredName string, dateOfBirth *time.Time, gender, pronouns *string) error
	// UpdatePatientContactInfo(ctx context.Context, userID uuid.UUID, address, city, province, postalCode, country, communicationMethod *string) error
	// UpdatePatientLanguagePreferences(ctx context.Context, userID uuid.UUID, languagePrefs []string, homeLanguage *string, requiresInterpreter bool) error
	// UpdatePatientMedicalAidInfo(ctx context.Context, userID uuid.UUID, medicalAidNumber, provider *string, hasMedicalAid bool) error
	// UpdatePatientDemographicInfo(ctx context.Context, userID uuid.UUID, employmentStatus, educationLevel, incomeRange *string) error
	// UpdatePatientProfilePicture(ctx context.Context, userID uuid.UUID, profilePictureURL *string) error
	// UpdatePatientTimezone(ctx context.Context, userID uuid.UUID, timezone string) error
	// UpdatePatientMarketingPreferences(ctx context.Context, userID uuid.UUID, acceptsMarketing bool) error
	// UpdatePatientReferralInfo(ctx context.Context, userID uuid.UUID, referredBy *uuid.UUID, referralCode *string) error
	//
	// // Search & Listing
	// SearchPatients(ctx context.Context, query string, province, city *string, hasMedicalAid, gender *string, limit, offset int) ([]patients.PatientProfile, error)
	// SearchPatientsByName(ctx context.Context, name string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByProvince(ctx context.Context, province string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByCity(ctx context.Context, city string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsWithMedicalAid(ctx context.Context, provider *string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsWithoutMedicalAid(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByLanguage(ctx context.Context, language string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsRequiringInterpreter(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByCommunicationMethod(ctx context.Context, method string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByReferrer(ctx context.Context, referrerID uuid.UUID, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByReferralCode(ctx context.Context, referralCode string) ([]patients.PatientProfile, error)
	// GetPatientsAcceptingMarketing(ctx context.Context, province *string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByAgeRange(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByGender(ctx context.Context, gender string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByIncomeRange(ctx context.Context, incomeRange string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientsByEmploymentStatus(ctx context.Context, employmentStatus string, limit, offset int) ([]patients.PatientProfile, error)
	// GetPatientProfilesByUserIDs(ctx context.Context, userIDs []uuid.UUID) ([]patients.PatientProfile, error)
	//
	// // Profile Completeness
	// GetIncompleteProfiles(ctx context.Context, checkMedicalAid bool, limit, offset int) ([]patients.PatientProfile, error)
	// GetRecentlyUpdatedProfiles(ctx context.Context, since time.Time, limit, offset int) ([]patients.PatientProfile, error)
	// GetStaleProfiles(ctx context.Context, olderThan time.Time, limit, offset int) ([]patients.PatientProfile, error)
	//
	// // Advanced Search
	// AdvancedPatientSearch(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error)
	//
	// // Analytics & Reporting
	// CountPatientsByProvince(ctx context.Context) (map[string]int64, error)
	// CountPatientsByMedicalAidStatus(ctx context.Context) (map[string]int64, error)
	// CountPatientsByCommunicationMethod(ctx context.Context) (map[string]int64, error)
	// GetPatientDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error)
	//
	// // Validation & Utilities
	// ValidatePatientExists(ctx context.Context, userID uuid.UUID) (bool, error)
	// GetPatientFullName(ctx context.Context, userID uuid.UUID) (string, error)
	// ExportPatientData(ctx context.Context, userID uuid.UUID) ([]patients.PatientProfile, error)
	//
	// // Bulk Operations
	// BulkUpdatePatientProvince(ctx context.Context, profileIDs []uuid.UUID, province string) error
	// BulkUpdateCommunicationMethod(ctx context.Context, profileIDs []uuid.UUID, method string) error
}

// ============================================
// CLINIC & PROVIDER MANAGEMENT
// ============================================

type ClinicRepository interface {
	// Clinic CRUD

	// Create
	CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error)

	// Read
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	ListClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error)
	// SearchClinics(ctx context.Context, query string, province *string, city *string, limit, offset int) ([]providers.Clinic, error)
	// SearchClinicsByLocation(ctx context.Context, latitude, longitude, radiusKm float64) ([]providers.Clinic, error)
	//
	// // Update
	// UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	// VerifyClinic(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error

	// Operating Hours
	// SetOperatingHours(ctx context.Context, hours providers.OperatingHours) error
	// GetOperatingHours(ctx context.Context, clinicID uuid.UUID) ([]providers.OperatingHours, error)
	// UpdateOperatingHours(ctx context.Context, hours providers.OperatingHours) error

	// Clinic Stats
	// GetClinicStats(ctx context.Context, clinicID uuid.UUID) (providers.ClinicStats, error)
	// GetClinicAppointmentSlots(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]providers.AppointmentSlot, error)
}

type StaffRepository interface {
	// Staff CRUD
	CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error)
	GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error)
	GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error
	DeleteStaffMember(ctx context.Context, id uuid.UUID) error

	// Clinic Staff Management
	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role string) ([]providers.ClinicStaff, error)
	GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	UpdateStaffStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateStaffRole(ctx context.Context, id uuid.UUID, role string) error
	TransferStaff(ctx context.Context, staffID, newClinicID uuid.UUID) error

	// Credentials & Verification
	AddCredential(ctx context.Context, cred providers.ProfessionalCredential) (providers.ProfessionalCredential, error)
	GetCredential(ctx context.Context, id uuid.UUID) (providers.ProfessionalCredential, error)
	GetCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	VerifyCredential(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error
	UpdateCredential(ctx context.Context, cred providers.ProfessionalCredential) error
	DeleteCredential(ctx context.Context, id uuid.UUID) error
	GetPendingCredentialVerifications(ctx context.Context) ([]providers.ProfessionalCredential, error)

	// Availability & Scheduling
	// SetStaffAvailability(ctx context.Context, availability providers.StaffAvailability) error
	// GetStaffAvailability(ctx context.Context, staffID uuid.UUID, startDate, endDate time.Time) ([]providers.StaffAvailability, error)
	// UpdateStaffAvailability(ctx context.Context, availability providers.StaffAvailability) error
}

type SMSRepository interface {
	// Conversation Management
	CreateConversation(ctx context.Context, conv sms.SMSConversation) (sms.SMSConversation, error)
	GetConversation(ctx context.Context, id uuid.UUID) (sms.SMSConversation, error)
	GetConversationByPhone(ctx context.Context, phone string) (sms.SMSConversation, error)
	GetConversationByUserID(ctx context.Context, userID uuid.UUID) (sms.SMSConversation, error)
	UpdateConversation(ctx context.Context, conv sms.SMSConversation) error
	CloseConversation(ctx context.Context, id uuid.UUID, reason string) error
	GetActiveConversations(ctx context.Context) ([]sms.SMSConversation, error)

	// Message Logging
	LogMessage(ctx context.Context, msg sms.SMSMessage) (sms.SMSMessage, error)
	GetMessage(ctx context.Context, id uuid.UUID) (sms.SMSMessage, error)
	GetConversationMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]sms.SMSMessage, error)
	//	GetMessagesByStatus(ctx context.Context, status sms.MessageStatus) ([]sms.SMSMessage, error)
	//	UpdateMessageStatus(ctx context.Context, messageID uuid.UUID, status sms.MessageStatus) error

	// Template Management
	// SaveSMSTemplate(ctx context.Context, template sms.SMSTemplate) (sms.SMSTemplate, error)
	// GetSMSTemplate(ctx context.Context, id uuid.UUID) (sms.SMSTemplate, error)
	// GetSMSTemplateByType(ctx context.Context, templateType string) (sms.SMSTemplate, error)
	// UpdateSMSTemplate(ctx context.Context, template sms.SMSTemplate) error

	// Analytics & Reporting
	//	GetSMSMetrics(ctx context.Context, startDate, endDate time.Time) (sms.SMSMetrics, error)
	GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]sms.SMSMessage, error)
	//	GetConversationStats(ctx context.Context, conversationID uuid.UUID) (sms.ConversationStats, error)

	// Compliance & Retention
	ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error
	ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error)
}

// ============================================
// APPOINTMENT MANAGEMENT
// ============================================

// ============================================
// BILLING & PAYMENTS
// ============================================

// ============================================
// PRESCRIPTION MANAGEMENT
// ============================================

// ============================================
// TRANSACTION MANAGEMENT
// ============================================

type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
	WithReadOnlyTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
	WithRetryTransaction(ctx context.Context, maxRetries int, fn func(context.Context, pgx.Tx) error) error
	GetTransaction(ctx context.Context) (pgx.Tx, bool)
}

// ============================================
// REPOSITORY FACTORY/COLLECTION
// ============================================

// type RepositoryProvider interface {
// 	// Core Repositories
// 	Auth() AuthRepository
// 	User() UserRepository
// 	OTP() OTPRepository
// 	Session() SessionRepository
//
// 	// Patient Domain
// 	Patient() PatientRepository
//
// 	// Provider Domain
// 	Clinic() ClinicRepository
// 	Staff() StaffRepository
//
// 	// Compliance & Audit
// 	Consent() ConsentRepository
// 	Audit() AuditRepository
//
// 	// Communication
// 	Notification() NotificationRepository
// 	SMS() SMSRepository
//
// 	// Business Logic
// 	Appointment() AppointmentRepository
// 	Billing() BillingRepository
// 	Prescription() PrescriptionRepository
//
// 	// Transaction Management
// 	Transaction() TxManager
//
// 	// Health & Connection
// 	HealthCheck(ctx context.Context) error
// 	Close() error
// }
