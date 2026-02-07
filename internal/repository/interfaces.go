package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"

	"github.com/jackc/pgx/v5"
)

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

	// UpdateUserOnboardingStep updates the user's onboarding progress
	UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error

	// UpdateUserPrimaryClinic sets the user's primary clinic
	UpdateUserPrimaryClinic(ctx context.Context, userID uuid.UUID, clinicID uuid.UUID) error

	// CompleteUserOnboarding marks onboarding as complete
	CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error

	// GetProviderWithClinic gets user with their clinic info
	GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error)

	// GetUserClinics gets all clinics a user is affiliated with
	GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error)
}

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
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	DeletePatientProfile(ctx context.Context, id uuid.UUID) error
	DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error

	ListPatientProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	SearchPatientProfiles(ctx context.Context, query string, limit, offset int) ([]patients.PatientProfile, error)

	ProfileExists(ctx context.Context, id uuid.UUID) (bool, error)
	ProfileExistsByUserID(ctx context.Context, userID uuid.UUID) (bool, error)
	NationalIDExists(ctx context.Context, nationalID string, excludeID *uuid.UUID) (bool, error)
}

type PatientMedicalInfoRepository interface {
	CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) (patients.PatientMedicalInfo, error)
	GetMedicalInfoByID(ctx context.Context, id uuid.UUID) (patients.PatientMedicalInfo, error)
	GetMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error)
	UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error
	DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error
}

type PatientSurgeryRepository interface {
	AddPatientSurgery(ctx context.Context, surgery patients.PatientSurgery) (patients.PatientSurgery, error)
	//	GetPatientSurgery(ctx context.Context, id uuid.UUID) (patients.PatientSurgery, error)
	UpdatePatientSurgery(ctx context.Context, surgery patients.PatientSurgery) error
	DeletePatientSurgery(ctx context.Context, id uuid.UUID) error
	//	DeletePatientSurgeries(ctx context.Context, patientID uuid.UUID) error

	GetPatientSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
	GetRecentSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
}

type PatientMedicationRepository interface {
	AddPatientMedication(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error)
	//	GetPatientMedication(ctx context.Context, id uuid.UUID) (patients.PatientMedication, error)
	UpdatePatientMedication(ctx context.Context, medication patients.PatientMedication) error
	DeletePatientMedication(ctx context.Context, id uuid.UUID) error
	//	DeletePatientMedications(ctx context.Context, patientID uuid.UUID) error

	GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error)
	GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
}

type PatientImmunizationRepository interface {
	AddPatientImmunization(ctx context.Context, immunization patients.PatientImmunization) (patients.PatientImmunization, error)
	//	GetPatientImmunization(ctx context.Context, id uuid.UUID) (patients.PatientImmunization, error)
	UpdatePatientImmunization(ctx context.Context, immunization patients.PatientImmunization) error
	DeletePatientImmunization(ctx context.Context, id uuid.UUID) error
	//	DeletePatientImmunizations(ctx context.Context, patientID uuid.UUID) error

	GetPatientImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)

	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
}

type PatientFamilyHistoryRepository interface {
	AddFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) (patients.PatientFamilyHistory, error)
	//	GetFamilyHistoryEntry(ctx context.Context, id uuid.UUID) (patients.PatientFamilyHistory, error)
	UpdateFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) error
	DeleteFamilyHistory(ctx context.Context, id uuid.UUID) error
	//	DeletePatientFamilyHistory(ctx context.Context, patientID uuid.UUID) error

	GetPatientFamilyHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error)
}

type PatientDependentRepository interface {
	AddPatientDependent(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error)
	//	GetPatientDependent(ctx context.Context, id uuid.UUID) (patients.PatientDependent, error)
	UpdatePatientDependent(ctx context.Context, dependent patients.PatientDependent) error
	DeletePatientDependent(ctx context.Context, id uuid.UUID) error
	//	DeletePatientDependents(ctx context.Context, patientID uuid.UUID) error

	GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
	GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
}

type PatientConditionRepository interface {
	AddPatientCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error)
	//	GetPatientCondition(ctx context.Context, id uuid.UUID) (patients.PatientCondition, error)
	UpdatePatientCondition(ctx context.Context, condition patients.PatientCondition) error
	DeletePatientCondition(ctx context.Context, id uuid.UUID) error
	//	DeletePatientConditions(ctx context.Context, patientID uuid.UUID) error

	GetPatientConditions(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientCondition, error)
	GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
}

type PatientAllergyRepository interface {
	AddPatientAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error)
	// GetPatientAllergy(ctx context.Context, id uuid.UUID) (patients.PatientAllergy, error)
	UpdatePatientAllergy(ctx context.Context, allergy patients.PatientAllergy) error
	DeletePatientAllergy(ctx context.Context, id uuid.UUID) error
	// DeletePatientAllergies(ctx context.Context, patientID uuid.UUID) error

	GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
}

type EmergencyContactRepository interface {
	AddEmergencyContact(ctx context.Context, contact patients.EmergencyContact) (patients.EmergencyContact, error)
	//	GetEmergencyContact(ctx context.Context, id uuid.UUID) (patients.EmergencyContact, error)
	UpdateEmergencyContact(ctx context.Context, contact patients.EmergencyContact) error
	DeleteEmergencyContact(ctx context.Context, id uuid.UUID) error
	//	DeletePatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) error

	GetPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error)
	GetPrimaryEmergencyContact(ctx context.Context, patientID uuid.UUID) (patients.EmergencyContact, error)
}

type DependentHealthRecordRepository interface {
	// ===== Core CRUD Operations =====
	AddDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) (patients.DependentHealthRecord, error)
	//	GetDependentHealthRecord(ctx context.Context, id uuid.UUID) (patients.DependentHealthRecord, error)
	UpdateDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) error
	DeleteDependentHealthRecord(ctx context.Context, id uuid.UUID) error
	//	DeleteDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) error

	GetDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
}

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

type ClinicRepository interface {
	CreateClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	DeleteClinic(ctx context.Context, id uuid.UUID) error

	VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error
	DeactivateClinic(ctx context.Context, id uuid.UUID) error
	ReactivateClinic(ctx context.Context, id uuid.UUID) error

	SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error)

	GetClinics(ctx context.Context) ([]providers.Clinic, error)
}

type ServiceRepository interface {
	CreateClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error)
	GetServiceByID(ctx context.Context, id uuid.UUID) (providers.ClinicService, error)
	UpdateClinicService(ctx context.Context, service providers.ClinicService) error
	DeleteClinicService(ctx context.Context, id uuid.UUID) error

	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)

	ServiceExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error)
}

type StaffRepository interface {
	CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error)
	GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error
	DeleteStaffMember(ctx context.Context, id uuid.UUID) error

	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error)
	GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)

	StaffExists(ctx context.Context, id uuid.UUID) (bool, error)
}

type CredentialRepository interface {
	CreateCredential(ctx context.Context, credential providers.ProfessionalCredential) (providers.ProfessionalCredential, error)
	GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	DeleteCredential(ctx context.Context, id uuid.UUID) error
}

type SystemAdminRepository interface {
	CreateSystemAdmin(ctx context.Context, admin admin.SystemAdmin) (admin.SystemAdmin, error)
	//	GetSystemAdmin(ctx context.Context, id uuid.UUID) (admin.SystemAdmin, error)
	GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error)
	//	UpdateSystemAdmin(ctx context.Context, admin admin.SystemAdmin) error
	//	DeleteSystemAdmin(ctx context.Context, id uuid.UUID) error
}

type NGOPartnerRepository interface {
	CreateNGOPartner(ctx context.Context, partner admin.NGOPartner) (admin.NGOPartner, error)
	//	GetNGOPartner(ctx context.Context, id uuid.UUID) (admin.NGOPartner, error)
	GetNGOPartnerByUserID(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error)
	// UpdateNGOPartner(ctx context.Context, partner admin.NGOPartner) error
	// DeleteNGOPartner(ctx context.Context, id uuid.UUID) error
}

type AppointmentRepository interface {
	// Create
	BookAppointment(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error)

	// Read
	GetAppointmentByID(ctx context.Context, id uuid.UUID) (appointments.Appointment, error)
	GetAppointmentsByPatient(ctx context.Context, patientID uuid.UUID) ([]appointments.Appointment, error)
	GetAppointmentsByClinic(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error)
	GetAppointmentsByClinicAndDate(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]appointments.Appointment, error)
	GetTodayAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error)
	GetPendingAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error)
	GetAppointmentCount(ctx context.Context, patientID uuid.UUID) (int64, error)

	// Update
	RescheduleAppointment(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error)
	ConfirmAppointment(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error)
	UpdateAppointmentNotes(ctx context.Context, id uuid.UUID, notes string) (appointments.Appointment, error)
	CompleteAppointment(ctx context.Context, id uuid.UUID) (appointments.Appointment, error)
	CancelAppointment(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error)
	UpdateAppointmentStatus(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus) (appointments.Appointment, error)

	// Delete
	DeleteAppointment(ctx context.Context, id uuid.UUID) error

	// Utility
	CheckSchedulingConflict(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error)
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

	// Analytics & Reporting
	GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]sms.SMSMessage, error)

	// Compliance & Retention
	ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error
	ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error)
}

type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
	WithReadOnlyTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
	WithRetryTransaction(ctx context.Context, maxRetries int, fn func(context.Context, pgx.Tx) error) error
	GetTransaction(ctx context.Context) (pgx.Tx, bool)
}
