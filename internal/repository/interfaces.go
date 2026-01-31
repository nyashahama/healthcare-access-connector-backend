package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
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

type PatientProfileRepository interface {
	// ===== Core CRUD =====
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	DeletePatientProfile(ctx context.Context, id uuid.UUID) error
	DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error

	// ===== Basic Search =====
	ListPatientProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	SearchPatientProfiles(ctx context.Context, query string, limit, offset int) ([]patients.PatientProfile, error)

	// ===== Validation =====
	ProfileExists(ctx context.Context, id uuid.UUID) (bool, error)
	ProfileExistsByUserID(ctx context.Context, userID uuid.UUID) (bool, error)
	NationalIDExists(ctx context.Context, nationalID string, excludeID *uuid.UUID) (bool, error)
}

// ============================================
// PATIENT MEDICAL INFO REPOSITORY
// Maps to: patient_medical_info.sql
// Domain: Patient Vital Signs, Blood Type, Health Status, & Advance Directives
// ============================================

type PatientMedicalInfoRepository interface {
	// ===== Core CRUD Operations =====
	CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) (patients.PatientMedicalInfo, error)
	GetMedicalInfoByID(ctx context.Context, id uuid.UUID) (patients.PatientMedicalInfo, error)
	GetMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error)
	UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error
	DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error
}

// ============================================
// PATIENT SURGERY REPOSITORY
// Maps to: patient_surgeries.sql
// Domain: Surgical History, Procedures, & Outcomes Management
// ============================================

type PatientSurgeryRepository interface {
	// ===== Core CRUD Operations =====
	AddPatientSurgery(ctx context.Context, surgery patients.PatientSurgery) (patients.PatientSurgery, error)
	//	GetPatientSurgery(ctx context.Context, id uuid.UUID) (patients.PatientSurgery, error)
	UpdatePatientSurgery(ctx context.Context, surgery patients.PatientSurgery) error
	DeletePatientSurgery(ctx context.Context, id uuid.UUID) error
	//	DeletePatientSurgeries(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
	GetRecentSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
}

// ============================================
// PATIENT MEDICATION REPOSITORY
// Maps to: patient_medications.sql
// Domain: Medication Management, Prescriptions, & Pharmacy Records
// ============================================

type PatientMedicationRepository interface {
	// ===== Core CRUD Operations =====
	AddPatientMedication(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error)
	//	GetPatientMedication(ctx context.Context, id uuid.UUID) (patients.PatientMedication, error)
	UpdatePatientMedication(ctx context.Context, medication patients.PatientMedication) error
	DeletePatientMedication(ctx context.Context, id uuid.UUID) error
	//	DeletePatientMedications(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error)
	GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
}

// ============================================
// PATIENT IMMUNIZATION REPOSITORY
// Maps to: patient_immunizations.sql
// Domain: Vaccination Records, Schedules, & Coverage Tracking
// ============================================

type PatientImmunizationRepository interface {
	// ===== Core CRUD Operations =====
	AddPatientImmunization(ctx context.Context, immunization patients.PatientImmunization) (patients.PatientImmunization, error)
	//	GetPatientImmunization(ctx context.Context, id uuid.UUID) (patients.PatientImmunization, error)
	UpdatePatientImmunization(ctx context.Context, immunization patients.PatientImmunization) error
	DeletePatientImmunization(ctx context.Context, id uuid.UUID) error
	//	DeletePatientImmunizations(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)

	// ===== Due Date & Scheduling =====
	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
}

// ============================================
// PATIENT FAMILY HISTORY REPOSITORY
// Maps to: patient_family_history.sql
// Domain: Family Medical History, Genetic Risk Assessment, & Hereditary Conditions
// ============================================

type PatientFamilyHistoryRepository interface {
	// ===== Core CRUD Operations =====
	AddFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) (patients.PatientFamilyHistory, error)
	//	GetFamilyHistoryEntry(ctx context.Context, id uuid.UUID) (patients.PatientFamilyHistory, error)
	UpdateFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) error
	DeleteFamilyHistory(ctx context.Context, id uuid.UUID) error
	//	DeletePatientFamilyHistory(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientFamilyHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error)
}

// ============================================
// PATIENT DEPENDENT REPOSITORY
// Maps to: patient_dependents.sql
// Domain: Dependent (Children/Wards) Management & Growth Tracking
// ============================================

type PatientDependentRepository interface {
	// ===== Core CRUD Operations =====
	AddPatientDependent(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error)
	//	GetPatientDependent(ctx context.Context, id uuid.UUID) (patients.PatientDependent, error)
	UpdatePatientDependent(ctx context.Context, dependent patients.PatientDependent) error
	DeletePatientDependent(ctx context.Context, id uuid.UUID) error
	//	DeletePatientDependents(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
	GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
}

// ============================================
// PATIENT CONDITION REPOSITORY
// Maps to: patient_conditions.sql
// Domain: Medical Conditions, Diagnosis, & Disease Management
// ============================================

type PatientConditionRepository interface {
	// ===== Core CRUD Operations =====
	AddPatientCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error)
	//	GetPatientCondition(ctx context.Context, id uuid.UUID) (patients.PatientCondition, error)
	UpdatePatientCondition(ctx context.Context, condition patients.PatientCondition) error
	DeletePatientCondition(ctx context.Context, id uuid.UUID) error
	//	DeletePatientConditions(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientConditions(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientCondition, error)
	GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
}

// ============================================
// PATIENT ALLERGY REPOSITORY
// Maps to: patient_allergies.sql
// Domain: Allergy Management, Severity Tracking, & Safety Monitoring
// ============================================

type PatientAllergyRepository interface {
	// ===== Core CRUD Operations =====
	AddPatientAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error)
	// GetPatientAllergy(ctx context.Context, id uuid.UUID) (patients.PatientAllergy, error)
	UpdatePatientAllergy(ctx context.Context, allergy patients.PatientAllergy) error
	DeletePatientAllergy(ctx context.Context, id uuid.UUID) error
	// DeletePatientAllergies(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
}

// ============================================
// EMERGENCY CONTACT REPOSITORY
// Maps to: emergency_contacts.sql
// Domain: Emergency Contact Management & Medical Information Access Control
// ============================================

type EmergencyContactRepository interface {
	// ===== Core CRUD Operations =====
	AddEmergencyContact(ctx context.Context, contact patients.EmergencyContact) (patients.EmergencyContact, error)
	//	GetEmergencyContact(ctx context.Context, id uuid.UUID) (patients.EmergencyContact, error)
	UpdateEmergencyContact(ctx context.Context, contact patients.EmergencyContact) error
	DeleteEmergencyContact(ctx context.Context, id uuid.UUID) error
	//	DeletePatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) error

	// ===== Querying by Patient =====
	GetPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error)
	GetPrimaryEmergencyContact(ctx context.Context, patientID uuid.UUID) (patients.EmergencyContact, error)
}

// ============================================
// DEPENDENT HEALTH RECORD REPOSITORY
// Maps to: dependent_health_records.sql
// Domain: Dependent Health Records, Growth Tracking, & Pediatric Care
// ============================================

type DependentHealthRecordRepository interface {
	// ===== Core CRUD Operations =====
	AddDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) (patients.DependentHealthRecord, error)
	//	GetDependentHealthRecord(ctx context.Context, id uuid.UUID) (patients.DependentHealthRecord, error)
	UpdateDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) error
	DeleteDependentHealthRecord(ctx context.Context, id uuid.UUID) error
	//	DeleteDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) error

	// ===== Querying by Dependent =====
	GetDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
}

// ============================================
// NOTIFICATION REPOSITORY
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
// CLINIC REPOSITORY
// Maps to: clinics.sql
// Domain: Healthcare Facility Management
// ============================================

type ClinicRepository interface {
	// ===== Core CRUD Operations =====
	CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	DeleteClinic(ctx context.Context, id uuid.UUID) error

	// ===== Verification & Status =====
	VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error
	DeactivateClinic(ctx context.Context, id uuid.UUID) error
	ReactivateClinic(ctx context.Context, id uuid.UUID) error

	SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error)

	// ===== Filtering & Listing =====
	GetClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error)
}

// ============================================
// SERVICE REPOSITORY
// Maps to: clinic_services.sql
// Domain: Healthcare Service Management
// ============================================

type ServiceRepository interface {
	// ===== Core CRUD Operations =====
	CreateClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error)
	GetServiceByID(ctx context.Context, id uuid.UUID) (providers.ClinicService, error)
	UpdateClinicService(ctx context.Context, service providers.ClinicService) error
	DeleteClinicService(ctx context.Context, id uuid.UUID) error

	// ===== Basic Queries =====
	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)

	// ===== Validation =====
	ServiceExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error)
}

// ============================================
// STAFF REPOSITORY
// Maps to: clinic_staff.sql
// Domain: Healthcare Staff Management
// ============================================

type StaffRepository interface {
	// ===== Core CRUD Operations =====
	CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error)
	GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error
	DeleteStaffMember(ctx context.Context, id uuid.UUID) error

	// ===== Basic Queries =====
	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error)
	GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)

	// ===== Validation =====
	StaffExists(ctx context.Context, id uuid.UUID) (bool, error)
}

// ============================================
// CREDENTIAL REPOSITORY
// Maps to: professional_credentials.sql
// Domain: Professional Licensing & Certification Management
// ============================================

type CredentialRepository interface {
	// ===== Core CRUD Operations =====
	CreateCredential(ctx context.Context, credential providers.ProfessionalCredential) (providers.ProfessionalCredential, error)
	GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	DeleteCredential(ctx context.Context, id uuid.UUID) error
}

// ============================================
// SYSTEM ADMIN REPOSITORY
// Maps to: system_admin.sql
// Domain: System Administration & Access Management
// ============================================

type SystemAdminRepository interface {
	// ===== Core CRUD Operations =====
	CreateSystemAdmin(ctx context.Context, admin admin.SystemAdmin) (admin.SystemAdmin, error)
	//	GetSystemAdmin(ctx context.Context, id uuid.UUID) (admin.SystemAdmin, error)
	GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error)
	//	UpdateSystemAdmin(ctx context.Context, admin admin.SystemAdmin) error
	//	DeleteSystemAdmin(ctx context.Context, id uuid.UUID) error

	// ===== Permissions Management =====
	UpdateAdminPermissions(ctx context.Context, id uuid.UUID, permissions interface{}, canManageUsers, canManageClinics, canManageContent, canViewAnalytics, canManageSystem bool) error
	AddRegionAssignment(ctx context.Context, id uuid.UUID, region string) error
}

// ============================================
// NGO PARTNER REPOSITORY
// Maps to: ngo_partners.sql
// Domain: NGO Partnership Management & Collaboration
// ============================================

type NGOPartnerRepository interface {
	// ===== Core CRUD Operations =====
	CreateNGOPartner(ctx context.Context, partner admin.NGOPartner) (admin.NGOPartner, error)
	//	GetNGOPartner(ctx context.Context, id uuid.UUID) (admin.NGOPartner, error)
	GetNGOPartnerByUserID(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error)
	// UpdateNGOPartner(ctx context.Context, partner admin.NGOPartner) error
	// DeleteNGOPartner(ctx context.Context, id uuid.UUID) error

	UpdatePartnershipStatus(ctx context.Context, id uuid.UUID, status string) error
}

// ============================================
// SMS REPOSITORY
// ============================================

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

	// Analytics & Reporting
	GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]sms.SMSMessage, error)

	// Compliance & Retention
	ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error
	ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error)
}

// ============================================
// TRANSACTION MANAGEMENT
// ============================================

type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
	WithReadOnlyTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
	WithRetryTransaction(ctx context.Context, maxRetries int, fn func(context.Context, pgx.Tx) error) error
	GetTransaction(ctx context.Context) (pgx.Tx, bool)
}
