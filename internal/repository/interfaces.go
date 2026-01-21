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
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error
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
// COMPLIANCE & AUDIT (POPIA/GDPR)
// ============================================

type ConsentRepository interface {
	// Consent Management
	CreateConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, consent core.PrivacyConsent) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error

	// Consent Tracking
	GetConsentHistory(ctx context.Context, userID uuid.UUID) ([]core.PrivacyConsent, error)
	GetActiveConsentsByType(ctx context.Context, consentType string) ([]core.PrivacyConsent, error)
	GetExpiredConsents(ctx context.Context) ([]core.PrivacyConsent, error)

	// Compliance Reporting
	//	GetConsentComplianceReport(ctx context.Context, startDate, endDate time.Time) (core.ComplianceReport, error)
	ExportConsentData(ctx context.Context, userID uuid.UUID) ([]byte, error)

	// Bulk Operations
	//	BulkUpdateConsents(ctx context.Context, updates []core.PrivacyConsentUpdate) error
	NotifyConsentExpirations(ctx context.Context, daysBefore int) ([]uuid.UUID, error)
}

type AuditRepository interface {
	// Activity Logging
	LogActivity(ctx context.Context, activity core.UserActivity) error
	GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error)
	GetActivitiesByType(ctx context.Context, activityType string, startDate, endDate time.Time) ([]core.UserActivity, error)

	// Data Access Logging (POPIA Compliance)
	LogDataAccess(ctx context.Context, access core.DataAccessLog) error
	GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
	GetDataAccessLogsByAccessor(ctx context.Context, accessedByUserID uuid.UUID, limit, offset int) ([]core.DataAccessLog, error)
	GetEmergencyAccessLogs(ctx context.Context, limit, offset int) ([]core.DataAccessLog, error)

	// Audit Reports
	//	GenerateAccessReport(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) (core.AccessReport, error)
	//	GenerateComplianceReport(ctx context.Context, startDate, endDate time.Time) (core.ComplianceReport, error)

	// Retention & Cleanup
	ArchiveOldLogs(ctx context.Context, olderThan time.Duration) error
	DeleteArchivedLogs(ctx context.Context, olderThan time.Duration) error

	// Security Monitoring
	GetSuspiciousActivities(ctx context.Context, threshold int) ([]core.UserActivity, error)
	GetFailedLoginAttempts(ctx context.Context, within time.Duration) ([]core.UserActivity, error)
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

type PatientRepository interface {
	// Patient Profile
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	DeletePatientProfile(ctx context.Context, id uuid.UUID) error

	// Search & Filtering
	SearchPatients(ctx context.Context, query string, province string, limit, offset int) ([]patients.PatientProfile, error)
	// FilterPatients(ctx context.Context, filters patients.PatientFilters) ([]patients.PatientProfile, error)
	GetPatientsByClinic(ctx context.Context, clinicID uuid.UUID, limit, offset int) ([]patients.PatientProfile, error)

	// Medical Information
	CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error
	GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error)
	UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error
	DeleteMedicalInfo(ctx context.Context, patientID uuid.UUID) error

	// Allergies
	AddAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error)
	GetAllergy(ctx context.Context, id uuid.UUID) (patients.PatientAllergy, error)
	GetAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	UpdateAllergy(ctx context.Context, allergy patients.PatientAllergy) error
	DeleteAllergy(ctx context.Context, id uuid.UUID) error

	// Medications
	AddMedication(ctx context.Context, med patients.PatientMedication) (patients.PatientMedication, error)
	GetMedication(ctx context.Context, id uuid.UUID) (patients.PatientMedication, error)
	GetMedications(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientMedication, error)
	UpdateMedication(ctx context.Context, med patients.PatientMedication) error
	DeleteMedication(ctx context.Context, id uuid.UUID) error
	GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)

	// Conditions
	AddCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error)
	GetCondition(ctx context.Context, id uuid.UUID) (patients.PatientCondition, error)
	GetConditions(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientCondition, error)
	UpdateCondition(ctx context.Context, condition patients.PatientCondition) error
	DeleteCondition(ctx context.Context, id uuid.UUID) error
	GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)

	// Immunizations
	AddImmunization(ctx context.Context, imm patients.PatientImmunization) (patients.PatientImmunization, error)
	GetImmunization(ctx context.Context, id uuid.UUID) (patients.PatientImmunization, error)
	GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	UpdateImmunization(ctx context.Context, imm patients.PatientImmunization) error
	DeleteImmunization(ctx context.Context, id uuid.UUID) error
	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	GetImmunizationHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)

	// Documents & Attachments
	// AddDocument(ctx context.Context, doc patients.PatientDocument) (patients.PatientDocument, error)
	// GetDocument(ctx context.Context, id uuid.UUID) (patients.PatientDocument, error)
	// GetDocuments(ctx context.Context, patientID uuid.UUID, docType string) ([]patients.PatientDocument, error)
	// UpdateDocument(ctx context.Context, doc patients.PatientDocument) error
	// DeleteDocument(ctx context.Context, id uuid.UUID) error
}

// ============================================
// CLINIC & PROVIDER MANAGEMENT
// ============================================

type ClinicRepository interface {
	// Clinic CRUD
	CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	DeleteClinic(ctx context.Context, id uuid.UUID) error

	// Verification & Status
	VerifyClinic(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error
	UpdateClinicStatus(ctx context.Context, id uuid.UUID, status string) error
	GetPendingVerifications(ctx context.Context, limit, offset int) ([]providers.Clinic, error)

	// Search & Discovery
	ListClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error)
	SearchClinics(ctx context.Context, query string, province string, city string, limit, offset int) ([]providers.Clinic, error)
	SearchClinicsByLocation(ctx context.Context, lat, lng float64, radiusKm float64) ([]providers.Clinic, error)
	GetFeaturedClinics(ctx context.Context, limit int) ([]providers.Clinic, error)
	GetClinicsByService(ctx context.Context, serviceID uuid.UUID) ([]providers.Clinic, error)

	// Clinic Services
	AddClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error)
	GetClinicService(ctx context.Context, id uuid.UUID) (providers.ClinicService, error)
	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	UpdateClinicService(ctx context.Context, service providers.ClinicService) error
	DeactivateClinicService(ctx context.Context, id uuid.UUID) error

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
