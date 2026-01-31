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
// PATIENT REPOSITORY
// Maps to: patient_profiles.sql & related health records tables
// ============================================

type PatientProfileRepository interface {
	// ===== Core CRUD Operations =====
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	DeletePatientProfile(ctx context.Context, id uuid.UUID) error
	DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error

	// ===== Personal Information Updates =====
	UpdatePersonalInfo(ctx context.Context, id uuid.UUID, firstName, lastName string, preferredName *string) error
	UpdateDateOfBirth(ctx context.Context, id uuid.UUID, dob time.Time) error
	UpdateGenderInfo(ctx context.Context, id uuid.UUID, gender *string, pronouns *string) error
	UpdateProfilePicture(ctx context.Context, id uuid.UUID, pictureURL string) error
	UpdatePreferredName(ctx context.Context, id uuid.UUID, preferredName *string) error

	// ===== Contact Information Updates =====
	UpdateContactInfo(ctx context.Context, id uuid.UUID, address, city, province, postalCode *string) error
	UpdateAddress(ctx context.Context, id uuid.UUID, address, city, province, postalCode, country *string) error
	UpdatePrimaryAddress(ctx context.Context, id uuid.UUID, address string) error
	UpdateLocation(ctx context.Context, id uuid.UUID, city, province *string) error

	// ===== Communication Preferences =====
	UpdateCommunicationPreferences(ctx context.Context, id uuid.UUID, method string, languages []string) error
	UpdatePreferredCommunicationMethod(ctx context.Context, id uuid.UUID, method string) error
	UpdateLanguagePreferences(ctx context.Context, id uuid.UUID, languages []string) error
	UpdateHomeLanguage(ctx context.Context, id uuid.UUID, language string) error
	UpdateInterpreterRequirement(ctx context.Context, id uuid.UUID, requiresInterpreter bool) error

	// ===== Medical Aid Information =====
	UpdateMedicalAidInfo(ctx context.Context, id uuid.UUID, hasMedicalAid bool, provider, number *string) error
	UpdateMedicalAidNumber(ctx context.Context, id uuid.UUID, number string) error
	UpdateMedicalAidProvider(ctx context.Context, id uuid.UUID, provider string) error
	UpdateMedicalAidStatus(ctx context.Context, id uuid.UUID, hasMedicalAid bool) error

	// ===== Health System Identifiers =====
	UpdateNationalIDNumber(ctx context.Context, id uuid.UUID, nationalID string) error
	UpdateHealthSystemIdentifiers(ctx context.Context, id uuid.UUID, nationalID *string, medicalAidNumber *string) error

	// ===== Demographic & Socioeconomic Information =====
	UpdateEmploymentStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateEducationLevel(ctx context.Context, id uuid.UUID, level string) error
	UpdateHouseholdIncomeRange(ctx context.Context, id uuid.UUID, incomeRange string) error
	UpdateDemographicInfo(ctx context.Context, id uuid.UUID, employmentStatus, educationLevel, incomeRange *string) error

	// ===== Profile Settings & Preferences =====
	UpdateTimezone(ctx context.Context, id uuid.UUID, timezone string) error
	UpdateMarketingPreferences(ctx context.Context, id uuid.UUID, acceptsMarketing bool) error
	UpdateReferralInfo(ctx context.Context, id uuid.UUID, referredBy *uuid.UUID, referralCode *string) error
	UpdateLastProfileUpdate(ctx context.Context, id uuid.UUID) error

	// ===== Querying & Search =====
	ListPatientProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	SearchPatientProfiles(ctx context.Context, query string, limit, offset int) ([]patients.PatientProfile, error)
	AdvancedSearchPatients(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error)

	// ===== Geographic Queries =====
	GetPatientsByProvince(ctx context.Context, province string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsByCity(ctx context.Context, city string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsByProvinceAndCity(ctx context.Context, province, city string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsInArea(ctx context.Context, province, city *string) ([]patients.PatientProfile, error)

	// ===== Medical Aid Queries =====
	GetPatientsByMedicalAidProvider(ctx context.Context, provider string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsWithMedicalAid(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsWithoutMedicalAid(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)

	// ===== Communication & Language Queries =====
	GetPatientsByPreferredLanguage(ctx context.Context, language string) ([]patients.PatientProfile, error)
	GetPatientsRequiringInterpreter(ctx context.Context) ([]patients.PatientProfile, error)
	GetPatientsByHomeLanguage(ctx context.Context, language string) ([]patients.PatientProfile, error)
	GetPatientsByCommunicationMethod(ctx context.Context, method string, limit, offset int) ([]patients.PatientProfile, error)

	// ===== Demographic Queries =====
	GetPatientsByGender(ctx context.Context, gender string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsByAgeRange(ctx context.Context, minAge, maxAge int, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsByEmploymentStatus(ctx context.Context, status string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsByEducationLevel(ctx context.Context, level string, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsByIncomeRange(ctx context.Context, incomeRange string, limit, offset int) ([]patients.PatientProfile, error)

	// ===== Marketing & Consent =====
	GetPatientsAcceptingMarketing(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	GetPatientsOptedOutOfMarketing(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)

	// ===== Referral Queries =====
	GetPatientsByReferrer(ctx context.Context, referrerID uuid.UUID) ([]patients.PatientProfile, error)
	GetPatientsByReferralCode(ctx context.Context, referralCode string) ([]patients.PatientProfile, error)
	GetReferralStatistics(ctx context.Context, referrerID uuid.UUID) (int64, error)

	// ===== Profile Completion & Quality =====
	GetIncompleteProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error)
	GetProfilesWithMissingContactInfo(ctx context.Context) ([]patients.PatientProfile, error)
	GetProfilesWithMissingDemographics(ctx context.Context) ([]patients.PatientProfile, error)
	GetRecentlyUpdatedProfiles(ctx context.Context, since time.Time, limit, offset int) ([]patients.PatientProfile, error)
	GetStaleProfiles(ctx context.Context, olderThan time.Time) ([]patients.PatientProfile, error)

	// ===== Statistics & Analytics =====
	GetPatientDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error)
	GetProvinceDistribution(ctx context.Context) (map[string]int64, error)
	GetCityDistribution(ctx context.Context, province *string) (map[string]int64, error)
	GetGenderDistribution(ctx context.Context) (map[string]int64, error)
	GetAgeDistribution(ctx context.Context) (map[string]int64, error)
	GetMedicalAidProviderDistribution(ctx context.Context) (map[string]int64, error)
	GetLanguageDistribution(ctx context.Context) (map[string]int64, error)
	GetCommunicationMethodDistribution(ctx context.Context) (map[string]int64, error)
	GetEmploymentStatusDistribution(ctx context.Context) (map[string]int64, error)
	GetEducationLevelDistribution(ctx context.Context) (map[string]int64, error)
	GetIncomeRangeDistribution(ctx context.Context) (map[string]int64, error)

	// ===== Counting & Existence Checks =====
	CountPatientProfiles(ctx context.Context) (int64, error)
	CountPatientsByProvince(ctx context.Context, province string) (int64, error)
	CountPatientsByCity(ctx context.Context, city string) (int64, error)
	CountPatientsWithMedicalAid(ctx context.Context) (int64, error)
	CountPatientsRequiringInterpreter(ctx context.Context) (int64, error)
	CountPatientsAcceptingMarketing(ctx context.Context) (int64, error)
	ProfileExists(ctx context.Context, id uuid.UUID) (bool, error)
	ProfileExistsByUserID(ctx context.Context, userID uuid.UUID) (bool, error)
	NationalIDExists(ctx context.Context, nationalID string, excludeID *uuid.UUID) (bool, error)

	// ===== Bulk Operations =====
	GetPatientsByIDs(ctx context.Context, ids []uuid.UUID) ([]patients.PatientProfile, error)
	GetPatientsByUserIDs(ctx context.Context, userIDs []uuid.UUID) ([]patients.PatientProfile, error)
	BulkUpdateCommunicationMethod(ctx context.Context, ids []uuid.UUID, method string) error
	BulkUpdateMarketingPreferences(ctx context.Context, ids []uuid.UUID, acceptsMarketing bool) error
	BulkUpdateTimezone(ctx context.Context, ids []uuid.UUID, timezone string) error

	// ===== Compliance & Data Management =====
	ExportPatientData(ctx context.Context, patientID uuid.UUID) ([]byte, error)
	AnonymizePatientProfile(ctx context.Context, id uuid.UUID) error
	GetProfilesForDataRetentionReview(ctx context.Context, inactiveDays int) ([]patients.PatientProfile, error)

	// ===== Time-based Queries =====
	GetProfilesCreatedBetween(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]patients.PatientProfile, error)
	GetProfilesUpdatedBetween(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]patients.PatientProfile, error)
	GetNewPatientsInPeriod(ctx context.Context, startDate, endDate time.Time) ([]patients.PatientProfile, error)

	// ===== Reporting =====
	GeneratePatientDemographicsReport(ctx context.Context, startDate, endDate *time.Time) (interface{}, error)
	GenerateGeographicDistributionReport(ctx context.Context) (interface{}, error)
	GenerateMedicalAidCoverageReport(ctx context.Context) (interface{}, error)
	GetPatientGrowthMetrics(ctx context.Context, startDate, endDate time.Time) (interface{}, error)
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
	DeleteMedicalInfo(ctx context.Context, id uuid.UUID) error
	DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error

	// ===== Blood Type Management =====
	UpdateBloodType(ctx context.Context, id uuid.UUID, bloodType string, testedDate time.Time) error
	GetPatientsByBloodType(ctx context.Context, bloodType string, limit, offset int) ([]patients.PatientMedicalInfo, error)
	CountPatientsByBloodType(ctx context.Context, bloodType string) (int64, error)
	GetBloodTypeDistribution(ctx context.Context) (map[string]int64, error)

	// ===== Vital Signs & Measurements =====
	UpdateVitalStats(ctx context.Context, id uuid.UUID, heightCm, weightKg, bmi *float64, measuredDate time.Time) error
	UpdateHeight(ctx context.Context, id uuid.UUID, heightCm float64, measuredDate time.Time) error
	UpdateWeight(ctx context.Context, id uuid.UUID, weightKg float64, measuredDate time.Time) error
	UpdateBMI(ctx context.Context, id uuid.UUID, bmi float64) error
	GetPatientsByBMIRange(ctx context.Context, minBMI, maxBMI float64) ([]patients.PatientMedicalInfo, error)
	GetVitalStatistics(ctx context.Context) (patients.MedicalInfoSummary, error)

	// ===== Health Status Management =====
	UpdateHealthStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateHealthSummary(ctx context.Context, id uuid.UUID, summary string) error
	GetPatientsByHealthStatus(ctx context.Context, status string, limit, offset int) ([]patients.PatientMedicalInfo, error)
	CountPatientsByHealthStatus(ctx context.Context, status string) (int64, error)
	GetHealthStatusDistribution(ctx context.Context) (map[string]int64, error)

	// ===== Primary Care Provider =====
	UpdatePrimaryCareProvider(ctx context.Context, id uuid.UUID, physicianName string, clinicID *uuid.UUID) error
	UpdatePrimaryClinic(ctx context.Context, id uuid.UUID, clinicID uuid.UUID) error
	GetPatientsByPrimaryClinic(ctx context.Context, clinicID uuid.UUID) ([]patients.PatientMedicalInfo, error)
	GetPatientsByPhysician(ctx context.Context, physicianName string) ([]patients.PatientMedicalInfo, error)

	// ===== Advance Directives & End-of-Life =====
	UpdateOrganDonorStatus(ctx context.Context, id uuid.UUID, isOrganDonor bool) error
	UpdateDNRStatus(ctx context.Context, id uuid.UUID, dnrStatus bool) error
	UpdateAdvanceDirective(ctx context.Context, id uuid.UUID, exists bool, url *string) error
	GetOrganDonors(ctx context.Context, limit, offset int) ([]patients.PatientMedicalInfo, error)
	GetPatientsWithDNR(ctx context.Context) ([]patients.PatientMedicalInfo, error)
	GetPatientsWithAdvanceDirective(ctx context.Context) ([]patients.PatientMedicalInfo, error)
	CountOrganDonors(ctx context.Context) (int64, error)
	CountPatientsWithDNR(ctx context.Context) (int64, error)

	// ===== Statistics & Analytics =====
	GetMedicalInfoSummary(ctx context.Context) (patients.MedicalInfoSummary, error)
	GetAverageVitalsByAgeGroup(ctx context.Context) (interface{}, error)
	GetHealthTrends(ctx context.Context, startDate, endDate time.Time) (interface{}, error)

	// ===== Bulk Operations =====
	GetMedicalInfoByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientMedicalInfo, error)
	BulkUpdateHealthStatus(ctx context.Context, ids []uuid.UUID, status string) error

	// ===== Validation & Utilities =====
	MedicalInfoExists(ctx context.Context, patientID uuid.UUID) (bool, error)
	GetLastMeasurementDate(ctx context.Context, patientID uuid.UUID) (*time.Time, error)
	GetPatientsNeedingVitalUpdate(ctx context.Context, daysSinceUpdate int) ([]patients.PatientMedicalInfo, error)
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
	// GetSurgeriesWithComplications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
	//
	// // ===== Outcome & Complications Management =====
	// UpdateSurgeryOutcome(ctx context.Context, id uuid.UUID, outcome string, recoveryNotes *string) error
	// RecordComplications(ctx context.Context, id uuid.UUID, complications string, outcome *string) error
	// GetSurgeriesByOutcome(ctx context.Context, outcome string, limit, offset int) ([]patients.PatientSurgery, error)
	//
	// // ===== Search & Filtering =====
	// SearchSurgeriesByProcedure(ctx context.Context, patientID uuid.UUID, procedureName string) ([]patients.PatientSurgery, error)
	// GetPatientsByProcedure(ctx context.Context, procedureName string, limit, offset int) ([]patients.PatientSurgery, error)
	// GetSurgeriesBySurgeon(ctx context.Context, surgeonName string, limit, offset int) ([]patients.PatientSurgery, error)
	// GetSurgeriesByHospital(ctx context.Context, hospitalName string, limit, offset int) ([]patients.PatientSurgery, error)
	// GetSurgeriesByDateRange(ctx context.Context, startDate, endDate time.Time) ([]patients.PatientSurgery, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientSurgeries(ctx context.Context, patientID uuid.UUID) (patients.SurgeryStatistics, error)
	// GetSurgeryStatistics(ctx context.Context) (patients.SurgerySystemMetrics, error)
	// GetMostCommonProcedures(ctx context.Context, limit int) ([]patients.ProcedureStats, error)
	// GetSurgeryTrends(ctx context.Context, startDate time.Time) ([]patients.SurgeryTrend, error)
	// GetProcedureSuccessRate(ctx context.Context, procedureName string) (float64, error)
	// GetHospitalPerformanceMetrics(ctx context.Context, hospitalName string) (interface{}, error)
	//
	// // ===== Reporting Queries =====
	// GetPatientsWithMultipleSurgeries(ctx context.Context, minCount int) ([]interface{}, error)
	// GetRecentSurgicalPatients(ctx context.Context, since time.Time) ([]patients.PatientSurgery, error)
	// GetEmergencySurgeryInfo(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
	//
	// // ===== Bulk Operations =====
	// GetSurgeriesByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientSurgery, error)
	//
	// // ===== Validation & Utilities =====
	// HasSurgicalHistory(ctx context.Context, patientID uuid.UUID) (bool, error)
	// GetLastSurgeryDate(ctx context.Context, patientID uuid.UUID) (*time.Time, error)
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
	// GetCurrentMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
	// GetMedicationHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
	//
	// // ===== Status Management =====
	// UpdateMedicationStatus(ctx context.Context, id uuid.UUID, status string) error
	// DiscontinueMedication(ctx context.Context, id uuid.UUID, endDate *time.Time, instructions *string) error
	// CompleteMedication(ctx context.Context, id uuid.UUID) error
	// ReactivateMedication(ctx context.Context, id uuid.UUID) error
	//
	// // ===== Side Effects & Monitoring =====
	// RecordSideEffects(ctx context.Context, id uuid.UUID, sideEffects string) error
	// GetMedicationsWithSideEffects(ctx context.Context) ([]patients.PatientMedication, error)
	// GetMedicationsByRoute(ctx context.Context, patientID uuid.UUID, route string) ([]patients.PatientMedication, error)
	//
	// // ===== Prescriber & Pharmacy Queries =====
	// GetMedicationsByPrescriber(ctx context.Context, prescriberName string, limit, offset int) ([]patients.PatientMedication, error)
	// GetMedicationsByPharmacy(ctx context.Context, pharmacyName string, limit, offset int) ([]patients.PatientMedication, error)
	// UpdatePharmacy(ctx context.Context, id uuid.UUID, pharmacyName string) error
	//
	// // ===== Expiration & Refill Management =====
	// GetExpiringMedications(ctx context.Context, beforeDate time.Time) ([]patients.PatientMedication, error)
	// GetExpiredMedications(ctx context.Context) ([]patients.PatientMedication, error)
	// UpdateMedicationEndDate(ctx context.Context, id uuid.UUID, endDate time.Time) error
	//
	// // ===== Search & Filtering =====
	// SearchMedicationsByName(ctx context.Context, patientID uuid.UUID, searchTerm string) ([]patients.PatientMedication, error)
	// GetPatientsByMedication(ctx context.Context, medicationName string) ([]patients.PatientMedication, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientMedications(ctx context.Context, patientID uuid.UUID) (patients.MedicationStatistics, error)
	// GetMedicationStatistics(ctx context.Context) (patients.MedicationSystemMetrics, error)
	// GetMostPrescribedMedications(ctx context.Context, limit int) ([]patients.MedicationDistribution, error)
	// GetPrescriptionTrends(ctx context.Context, since time.Time) ([]patients.PrescriptionTrend, error)
	// GetPolypharmacyPatients(ctx context.Context, minMedications int) ([]interface{}, error)
	//
	// // ===== Reporting Queries =====
	// GetPatientsOnMultipleMedications(ctx context.Context, minCount int) ([]interface{}, error)
	// GetLongTermMedications(ctx context.Context, yearsOnMedication int) ([]patients.PatientMedication, error)
	// GetEmergencyMedicationInfo(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
	//
	// // ===== Bulk Operations =====
	// GetMedicationsByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientMedication, error)
	// BulkUpdateMedicationStatus(ctx context.Context, ids []uuid.UUID, status string) error
	//
	// // ===== Validation & Utilities =====
	// CheckMedicationConflict(ctx context.Context, patientID uuid.UUID, medicationName string, excludeID *uuid.UUID) (bool, error)
	// GetActiveMedicationCount(ctx context.Context, patientID uuid.UUID) (int64, error)
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
	// GetImmunizationHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	// GetImmunizationsByType(ctx context.Context, patientID uuid.UUID, vaccineType string) ([]patients.PatientImmunization, error)
	// GetRoutineImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)

	// ===== Due Date & Scheduling =====
	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	// GetOverdueImmunizations(ctx context.Context) ([]patients.PatientImmunization, error)
	// GetImmunizationsDueInPeriod(ctx context.Context, beforeDate time.Time) ([]patients.PatientImmunization, error)
	// UpdateNextDueDate(ctx context.Context, id uuid.UUID, nextDueDate time.Time) error
	//
	// // ===== Vaccine Series Tracking =====
	// GetIncompleteVaccineSeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	// GetCompleteVaccineSeries(ctx context.Context, patientID uuid.UUID) ([]interface{}, error)
	// GetVaccineSeriesProgress(ctx context.Context, patientID uuid.UUID) ([]patients.VaccineSeriesProgress, error)
	// IsVaccineSeriesComplete(ctx context.Context, patientID uuid.UUID, vaccineName string) (bool, error)
	//
	// // ===== Vaccine & Provider Queries =====
	// GetImmunizationsByVaccine(ctx context.Context, vaccineName string, limit, offset int) ([]patients.PatientImmunization, error)
	// GetImmunizationsByAdministrator(ctx context.Context, administratorName string, limit, offset int) ([]patients.PatientImmunization, error)
	// GetImmunizationsByClinic(ctx context.Context, clinicName string, limit, offset int) ([]patients.PatientImmunization, error)
	// GetImmunizationsByLotNumber(ctx context.Context, lotNumber string) ([]patients.PatientImmunization, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientImmunizations(ctx context.Context, patientID uuid.UUID) (patients.ImmunizationStatistics, error)
	// GetImmunizationStatistics(ctx context.Context) (patients.ImmunizationSystemMetrics, error)
	// GetVaccineDistribution(ctx context.Context) ([]patients.VaccineDistribution, error)
	// GetImmunizationCoverage(ctx context.Context) ([]patients.VaccineCoverage, error)
	// GetVaccinationRates(ctx context.Context, vaccineType *string) (interface{}, error)
	//
	// // ===== Compliance & Reporting =====
	// GetPatientsNeedingImmunizations(ctx context.Context) ([]interface{}, error)
	// GetChildrenNeedingVaccines(ctx context.Context, limit, offset int) ([]interface{}, error)
	// GetImmunizationRecordsByDateRange(ctx context.Context, startDate, endDate time.Time) ([]patients.PatientImmunization, error)
	// GetImmunizationGaps(ctx context.Context, patientID uuid.UUID) ([]interface{}, error)
	//
	// // ===== Bulk Operations =====
	// GetImmunizationsByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientImmunization, error)
	//
	// // ===== Validation & Utilities =====
	// CheckVaccineReceived(ctx context.Context, patientID uuid.UUID, vaccineName string) (bool, error)
	// GetLastVaccineDate(ctx context.Context, patientID uuid.UUID, vaccineName string) (*time.Time, error)
	//
	// // ===== Emergency Access =====
	// GetEmergencyImmunizationInfo(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
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
	// GetFamilyHistoryByRelative(ctx context.Context, patientID uuid.UUID, relative string) ([]patients.PatientFamilyHistory, error)
	// GetFamilyHistoryByCondition(ctx context.Context, patientID uuid.UUID, conditionName string) ([]patients.PatientFamilyHistory, error)
	//
	// // ===== Genetic Risk Assessment =====
	// GetGeneticConditions(ctx context.Context, patientID uuid.UUID) ([]patients.GeneticConditionRisk, error)
	// GetHeritableConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error)
	// GetPatientsWithFamilyCondition(ctx context.Context, conditionName string, limit, offset int) ([]patients.PatientFamilyHistory, error)
	// CalculateGeneticRisk(ctx context.Context, patientID uuid.UUID, conditionName string) (interface{}, error)
	//
	// // ===== Mortality Tracking =====
	// GetDeceasedRelatives(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error)
	// GetEarlyDeaths(ctx context.Context, maxAge int) ([]patients.PatientFamilyHistory, error)
	// GetMortalityPatterns(ctx context.Context, patientID uuid.UUID) (interface{}, error)
	//
	// // ===== Statistics & Analytics =====
	// CountFamilyHistoryEntries(ctx context.Context, patientID uuid.UUID) (patients.FamilyHistoryStatistics, error)
	// GetFamilyHistoryStatistics(ctx context.Context) (patients.FamilyHistorySystemMetrics, error)
	// GetMostCommonFamilyConditions(ctx context.Context, limit int) ([]patients.FamilyConditionStats, error)
	// GetHereditaryConditionPrevalence(ctx context.Context) (map[string]int64, error)
	//
	// // ===== Bulk Operations =====
	// GetFamilyHistoryByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientFamilyHistory, error)
	//
	// // ===== Validation & Utilities =====
	// HasFamilyHistory(ctx context.Context, patientID uuid.UUID) (bool, error)
	// HasConditionInFamily(ctx context.Context, patientID uuid.UUID, conditionName string) (bool, error)
	// CountRelativesWithCondition(ctx context.Context, patientID uuid.UUID, conditionName string) (int64, error)
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
	// GetDependentsByRelationship(ctx context.Context, patientID uuid.UUID, relationship string) ([]patients.PatientDependent, error)
	//
	// // ===== Health & Development Tracking =====
	// UpdateDependentHealth(ctx context.Context, id uuid.UUID, healthStatus string, pediatrician *string, clinicID *uuid.UUID) error
	// UpdateBirthMetrics(ctx context.Context, id uuid.UUID, birthWeightKg, birthHeightCm float64) error
	// GetDependentsByHealthStatus(ctx context.Context, healthStatus string) ([]patients.PatientDependent, error)
	//
	// // ===== Special Needs Management =====
	// GetDependentsWithSpecialNeeds(ctx context.Context) ([]patients.PatientDependent, error)
	// UpdateSpecialNeeds(ctx context.Context, id uuid.UUID, hasSpecialNeeds bool, description *string) error
	//
	// // ===== Guardianship & Legal =====
	// UpdateGuardianship(ctx context.Context, id uuid.UUID, hasGuardianship bool, documentURL *string) error
	// GetDependentsWithoutGuardianship(ctx context.Context) ([]patients.PatientDependent, error)
	//
	// // ===== Education & School =====
	// UpdateSchoolInfo(ctx context.Context, id uuid.UUID, schoolName, grade *string) error
	// GetDependentsBySchool(ctx context.Context, schoolName string) ([]patients.PatientDependent, error)
	// GetSchoolAgeChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
	//
	// // ===== Healthcare Provider Tracking =====
	// UpdatePediatrician(ctx context.Context, id uuid.UUID, pediatricianName string, clinicID *uuid.UUID) error
	// GetDependentsByPediatrician(ctx context.Context, pediatricianName string) ([]patients.PatientDependent, error)
	// GetDependentsByClinic(ctx context.Context, clinicID uuid.UUID) ([]patients.PatientDependent, error)
	//
	// // ===== Age & Demographic Queries =====
	// GetDependentsByAgeRange(ctx context.Context, patientID uuid.UUID, minAge, maxAge int) ([]patients.PatientDependent, error)
	// GetInfants(ctx context.Context) ([]patients.PatientDependent, error)
	// GetToddlers(ctx context.Context) ([]patients.PatientDependent, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientDependents(ctx context.Context, patientID uuid.UUID) (patients.DependentStatistics, error)
	// GetDependentStatistics(ctx context.Context) (patients.DependentSystemMetrics, error)
	// GetDependentAgeDistribution(ctx context.Context) ([]patients.AgeGroupDistribution, error)
	//
	// // ===== Bulk Operations =====
	// GetDependentsByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientDependent, error)
	//
	// // ===== Validation & Utilities =====
	// HasDependents(ctx context.Context, patientID uuid.UUID) (bool, error)
	// GetDependentAge(ctx context.Context, id uuid.UUID) (int, error)
	// GetDependentFullName(ctx context.Context, id uuid.UUID) (string, error)
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
	// GetChronicConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
	// GetAcuteConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
	// GetConditionsByType(ctx context.Context, patientID uuid.UUID, conditionType string) ([]patients.PatientCondition, error)
	//
	// // ===== Status Management =====
	// UpdateConditionStatus(ctx context.Context, id uuid.UUID, status string, notes *string) error
	// MarkConditionResolved(ctx context.Context, id uuid.UUID, notes *string) error
	// MarkConditionInRemission(ctx context.Context, id uuid.UUID, notes *string) error
	// UpdateConditionSeverity(ctx context.Context, id uuid.UUID, severity string, notes *string) error
	//
	// // ===== Flare-Up & Checkup Tracking =====
	// RecordFlareUp(ctx context.Context, id uuid.UUID, flareUpDate time.Time, notes *string) error
	// UpdateNextCheckup(ctx context.Context, id uuid.UUID, checkupDate time.Time) error
	// GetUpcomingCheckups(ctx context.Context, beforeDate time.Time) ([]patients.PatientCondition, error)
	// GetOverdueCheckups(ctx context.Context) ([]patients.PatientCondition, error)
	// GetRecentFlareUps(ctx context.Context, since time.Time) ([]patients.PatientCondition, error)
	//
	// // ===== Search & Filtering =====
	// SearchConditionsByName(ctx context.Context, patientID uuid.UUID, searchTerm string) ([]patients.PatientCondition, error)
	// GetConditionsByICD10(ctx context.Context, icd10Code string) ([]patients.PatientCondition, error)
	// GetPatientsByCondition(ctx context.Context, conditionName string) ([]patients.PatientCondition, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientConditions(ctx context.Context, patientID uuid.UUID) (patients.ConditionStatistics, error)
	// GetConditionStatistics(ctx context.Context) (patients.ConditionSystemMetrics, error)
	// GetMostCommonConditions(ctx context.Context, limit int) ([]patients.ConditionDistribution, error)
	// GetConditionTypeDistribution(ctx context.Context) ([]patients.ConditionTypeDistribution, error)
	//
	// // ===== Reporting Queries =====
	// GetPatientsWithMultipleConditions(ctx context.Context, minCount int) ([]interface{}, error)
	// GetHighRiskPatients(ctx context.Context) ([]patients.HighRiskPatient, error)
	// GetEmergencyConditionInfo(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
	//
	// // ===== Bulk Operations =====
	// GetConditionsByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientCondition, error)
	// BulkUpdateConditionStatus(ctx context.Context, ids []uuid.UUID, status string) error
	//
	// // ===== Validation & Utilities =====
	// HasChronicConditions(ctx context.Context, patientID uuid.UUID) (bool, error)
	// CheckConditionExists(ctx context.Context, patientID uuid.UUID, conditionName string) (bool, error)
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
	// GetPatientAllergiesByStatus(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientAllergy, error)

	// ===== Severity-Based Queries =====
	// GetSevereAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	// GetLifeThreateningAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	// GetPatientsBySeverity(ctx context.Context, severity string) ([]patients.PatientAllergy, error)
	//
	// // ===== Status Management =====
	// UpdateAllergyStatus(ctx context.Context, id uuid.UUID, status string) error
	// MarkAllergyResolved(ctx context.Context, id uuid.UUID, notes *string) error
	// MarkAllergyInactive(ctx context.Context, id uuid.UUID, notes *string) error
	// ReactivateAllergy(ctx context.Context, id uuid.UUID) error
	//
	// // ===== Occurrence Tracking =====
	// RecordAllergyOccurrence(ctx context.Context, id uuid.UUID, occurrenceDate time.Time, reaction *string) error
	// UpdateLastOccurrence(ctx context.Context, id uuid.UUID, occurrenceDate time.Time) error
	// GetRecentAllergyOccurrences(ctx context.Context, since time.Time) ([]patients.PatientAllergy, error)
	//
	// // ===== Allergy Type Queries =====
	// GetPatientsByAllergyName(ctx context.Context, allergyName string) ([]patients.PatientAllergy, error)
	// SearchAllergiesByName(ctx context.Context, patientID uuid.UUID, searchTerm string) ([]patients.PatientAllergy, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientAllergies(ctx context.Context, patientID uuid.UUID) (patients.AllergyStatistics, error)
	// GetAllergySeverityDistribution(ctx context.Context) ([]patients.AllergySeverityDistribution, error)
	// GetMostCommonAllergies(ctx context.Context, limit int) ([]patients.AllergyDistribution, error)
	// GetAllergyStatistics(ctx context.Context) (patients.AllergySystemMetrics, error)
	//
	// // ===== Reporting Queries =====
	// GetPatientsWithMultipleAllergies(ctx context.Context, minCount int) ([]interface{}, error)
	// GetPatientsWithNoAllergies(ctx context.Context, limit, offset int) ([]interface{}, error)
	// GetUnresolvedAllergies(ctx context.Context, yearsActive int) ([]patients.PatientAllergy, error)
	// GetAllergiesByDateRange(ctx context.Context, startDate, endDate time.Time) ([]patients.PatientAllergy, error)
	//
	// // ===== Bulk Operations =====
	// GetAllergiesByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientAllergy, error)
	// BulkUpdateAllergyStatus(ctx context.Context, ids []uuid.UUID, status string) error
	//
	// // ===== Validation & Utilities =====
	// CheckAllergyExists(ctx context.Context, patientID uuid.UUID, allergyName string) (bool, error)
	// HasLifeThreateningAllergies(ctx context.Context, patientID uuid.UUID) (bool, error)
	// GetPatientAllergyCount(ctx context.Context, patientID uuid.UUID) (int64, error)
	//
	// // ===== Emergency Access =====
	// GetEmergencyAllergyInfo(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	// GetCriticalAllergyWarnings(ctx context.Context, patientID uuid.UUID) (patients.CriticalAllergyWarnings, error)
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
	// GetEmergencyContactsByRelationship(ctx context.Context, patientID uuid.UUID, relationship string) ([]patients.EmergencyContact, error)
	//
	// // ===== Primary Contact Management =====
	// SetPrimaryPatientContact(ctx context.Context, patientID, contactID uuid.UUID) error
	// UpdatePrimaryContact(ctx context.Context, id uuid.UUID) error
	// ClearPrimaryContacts(ctx context.Context, patientID uuid.UUID) error
	//
	// // ===== Access Level Management =====
	// UpdateAccessLevel(ctx context.Context, id uuid.UUID, canAccess bool, accessLevel string) error
	// GrantMedicalAccess(ctx context.Context, id uuid.UUID, accessLevel string) error
	// RevokeMedicalAccess(ctx context.Context, id uuid.UUID) error
	// GetContactsWithMedicalAccess(ctx context.Context, accessLevel *string) ([]patients.EmergencyContact, error)
	// GetFullAccessContacts(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error)
	//
	// // ===== Verification Management =====
	// VerifyRelationship(ctx context.Context, id uuid.UUID, notes string) error
	// UpdateVerificationNotes(ctx context.Context, id uuid.UUID, notes string) error
	// GetUnverifiedContacts(ctx context.Context) ([]patients.EmergencyContact, error)
	//
	// // ===== Contact Information Updates =====
	// UpdateContactPhone(ctx context.Context, id uuid.UUID, phoneNumber string) error
	// UpdateContactEmail(ctx context.Context, id uuid.UUID, email string) error
	// UpdateContactAddress(ctx context.Context, id uuid.UUID, address string) error
	// UpdateContactDetails(ctx context.Context, id uuid.UUID, phone, email, address *string) error
	//
	// // ===== Search & Filtering =====
	// SearchEmergencyContacts(ctx context.Context, searchTerm string) ([]patients.EmergencyContact, error)
	// GetContactsByPhone(ctx context.Context, phoneNumber string) ([]patients.EmergencyContact, error)
	//
	// // ===== Statistics & Analytics =====
	// CountPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) (patients.EmergencyContactStatistics, error)
	// GetEmergencyContactStatistics(ctx context.Context) (patients.EmergencyContactSystemMetrics, error)
	// GetRelationshipDistribution(ctx context.Context) ([]patients.RelationshipDistribution, error)
	// GetAccessLevelDistribution(ctx context.Context) ([]patients.AccessLevelDistribution, error)
	//
	// // ===== Reporting Queries =====
	// GetPatientsWithoutEmergencyContacts(ctx context.Context, limit, offset int) ([]interface{}, error)
	// GetPatientsWithoutPrimaryContact(ctx context.Context, limit, offset int) ([]interface{}, error)
	// GetContactsNeedingVerification(ctx context.Context, daysUnverified int) ([]patients.EmergencyContact, error)
	//
	// // ===== Bulk Operations =====
	// GetEmergencyContactsByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.EmergencyContact, error)
	// BulkVerifyContacts(ctx context.Context, ids []uuid.UUID) error
	//
	// // ===== Validation & Utilities =====
	// HasEmergencyContacts(ctx context.Context, patientID uuid.UUID) (bool, error)
	// HasPrimaryContact(ctx context.Context, patientID uuid.UUID) (bool, error)
	// CheckPhonePatientExists(ctx context.Context, patientID uuid.UUID, phoneNumber string, excludeID *uuid.UUID) (bool, error)
	//
	// // ===== Emergency Access =====
	// GetEmergencyContactInfo(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error)
	// GetEmergencyNotificationList(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error)
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
	//	GetHealthRecordsByType(ctx context.Context, dependentID uuid.UUID, recordType string) ([]patients.DependentHealthRecord, error)
	GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	// GetVaccinationRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	// GetCheckupRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	// GetEmergencyRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	//
	// // ===== Growth Tracking =====
	// GetLatestGrowthMeasurements(ctx context.Context, dependentID uuid.UUID) (patients.GrowthMeasurement, error)
	// GetWeightHistory(ctx context.Context, dependentID uuid.UUID) ([]patients.VitalHistory, error)
	// GetHeightHistory(ctx context.Context, dependentID uuid.UUID) ([]patients.VitalHistory, error)
	// GetHeadCircumferenceHistory(ctx context.Context, dependentID uuid.UUID) ([]patients.VitalHistory, error)
	// GetGrowthTrend(ctx context.Context, dependentID uuid.UUID) ([]patients.GrowthMeasurement, error)
	//
	// // ===== Vital Signs Tracking =====
	// GetTemperatureHistory(ctx context.Context, dependentID uuid.UUID) ([]patients.VitalHistory, error)
	// GetAbnormalTemperatures(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	//
	// // ===== Appointment Management =====
	// GetUpcomingAppointments(ctx context.Context) ([]patients.DependentHealthRecord, error)
	// UpdateNextAppointment(ctx context.Context, id uuid.UUID, appointmentDate time.Time) error
	//
	// // ===== Provider & Clinic Queries =====
	// GetRecordsByProvider(ctx context.Context, dependentID uuid.UUID, providerName string) ([]patients.DependentHealthRecord, error)
	// GetRecordsByClinic(ctx context.Context, dependentID uuid.UUID, clinicName string) ([]patients.DependentHealthRecord, error)
	// GetProviderList(ctx context.Context, dependentID uuid.UUID) ([]string, error)
	// GetClinicList(ctx context.Context, dependentID uuid.UUID) ([]string, error)
	//
	// // ===== Document Management =====
	// UpdateRecordDocuments(ctx context.Context, id uuid.UUID, documents interface{}) error
	// AddRecordDocument(ctx context.Context, id uuid.UUID, document interface{}) error
	// GetRecordsWithDocuments(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	//
	// // ===== Date Range Queries =====
	// GetRecordsByDateRange(ctx context.Context, dependentID uuid.UUID, startDate, endDate time.Time) ([]patients.DependentHealthRecord, error)
	// GetRecentRecords(ctx context.Context, dependentID uuid.UUID, monthsBack int) ([]patients.DependentHealthRecord, error)
	//
	// // ===== Statistics & Analytics =====
	// CountHealthRecords(ctx context.Context, dependentID uuid.UUID) (patients.HealthRecordStatistics, error)
	// GetRecordTypeDistribution(ctx context.Context, dependentID uuid.UUID) ([]patients.RecordTypeDistribution, error)
	// GetGrowthStatistics(ctx context.Context, dependentID uuid.UUID) (patients.GrowthStatistics, error)
	//
	// // ===== Bulk Operations =====
	// GetRecordsByDependentIDs(ctx context.Context, dependentIDs []uuid.UUID) ([]patients.DependentHealthRecord, error)
	//
	// // ===== Validation & Utilities =====
	// HasHealthRecords(ctx context.Context, dependentID uuid.UUID) (bool, error)
	// GetLastCheckupDate(ctx context.Context, dependentID uuid.UUID) (*time.Time, error)
	// GetLastGrowthCheckDate(ctx context.Context, dependentID uuid.UUID) (*time.Time, error)
}

// ============================================
// PATIENT SAFETY & COMPREHENSIVE REPOSITORY
// Combines allergies, conditions, and emergency contacts for safety-critical operations
// ============================================

type PatientSafetyRepository interface {
	// ===== Comprehensive Safety Profiles =====
	GetPatientSafetyProfile(ctx context.Context, patientID uuid.UUID) (patients.PatientSafetyProfile, error)
	GetPatientAllergyProfile(ctx context.Context, patientID uuid.UUID) (patients.PatientAllergyProfile, error)

	// ===== Critical Safety Information =====
	GetCriticalSafetyInfo(ctx context.Context, patientID uuid.UUID) (interface{}, error)
	GetDrugInteractionWarnings(ctx context.Context, patientID uuid.UUID, medicationName string) (interface{}, error)

	// ===== Emergency Response =====
	GetEmergencyResponseInfo(ctx context.Context, patientID uuid.UUID) (interface{}, error)
	GetPatientRiskAssessment(ctx context.Context, patientID uuid.UUID) (interface{}, error)
}

// ============================================
// COMPREHENSIVE PATIENT HEALTH REPOSITORY
// Combines all patient health records for unified access
// ============================================

type ComprehensiveHealthRepository interface {
	// ===== Comprehensive Health Records =====
	GetComprehensiveHealthRecord(ctx context.Context, patientID uuid.UUID) (patients.ComprehensiveHealthRecord, error)
	GetEmergencyHealthInfo(ctx context.Context, patientID uuid.UUID) (patients.EmergencyHealthInfo, error)

	// ===== Bulk Comprehensive Records =====
	GetComprehensiveHealthRecordsByIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.ComprehensiveHealthRecord, error)

	// ===== Export & Compliance =====
	ExportPatientHealthData(ctx context.Context, patientID uuid.UUID) ([]byte, error)
	AnonymizePatientHealthData(ctx context.Context, patientID uuid.UUID) error

	// ===== Health Record Analytics =====
	GetPatientHealthSummary(ctx context.Context, patientID uuid.UUID) (interface{}, error)
	GetPopulationHealthMetrics(ctx context.Context) (interface{}, error)
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

	// ===== Location Management =====
	UpdateClinicLocation(ctx context.Context, id uuid.UUID, location providers.ClinicLocation) error
	UpdateClinicCoordinates(ctx context.Context, id uuid.UUID, latitude, longitude float64) error

	// ===== Contact Information =====
	UpdateClinicContact(ctx context.Context, id uuid.UUID, contact providers.ClinicContact) error

	// ===== Services & Capabilities =====
	UpdateClinicServices(ctx context.Context, id uuid.UUID, services providers.ClinicServicesUpdate) error
	UpdateClinicOperatingHours(ctx context.Context, id uuid.UUID, hours map[string]any) error

	// ===== Payment & Insurance =====
	UpdateClinicPaymentInfo(ctx context.Context, id uuid.UUID, payment providers.ClinicPaymentInfo) error

	// ===== Accreditation & Certification =====

	UpdateClinicAccreditation(ctx context.Context, id uuid.UUID, accreditation providers.ClinicAccreditation) error
	// ===== Verification & Status =====
	VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error
	DeactivateClinic(ctx context.Context, id uuid.UUID) error
	ReactivateClinic(ctx context.Context, id uuid.UUID) error

	// ===== Ratings & Reviews =====
	UpdateClinicRating(ctx context.Context, id uuid.UUID, rating float64, reviewCount int) error
	IncrementReviewCount(ctx context.Context, id uuid.UUID) error

	// ===== Operational Metrics =====
	UpdateClinicCapacity(ctx context.Context, id uuid.UUID, patientCapacity, bedCount int) error
	UpdateAverageWaitTime(ctx context.Context, id uuid.UUID, minutes int) error

	// ===== Search & Discovery =====
	SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error)
	SearchClinicsByName(ctx context.Context, name string, province *string, limit, offset int) ([]providers.ClinicSearchResult, error)
	SearchClinicsByLocation(ctx context.Context, lat, lng, radiusKm float64, limit int) ([]providers.ClinicSearchResult, error)
	GetNearbyClinicsByService(ctx context.Context, lat, lng, radiusKm float64, service string, limit int) ([]providers.ClinicSearchResult, error)

	// ===== Filtering & Listing =====
	GetClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error)
	GetVerifiedClinics(ctx context.Context, limit, offset int) ([]providers.Clinic, error)
	GetPendingClinics(ctx context.Context, limit, offset int) ([]providers.Clinic, error)
	GetClinicsByProvince(ctx context.Context, province string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsByCity(ctx context.Context, province, city string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsByType(ctx context.Context, clinicType string, limit, offset int) ([]providers.Clinic, error)

	// ===== Services & Specialties =====
	GetClinicsByService(ctx context.Context, service string, province *string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsBySpecialty(ctx context.Context, specialty string, province *string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsWithFacility(ctx context.Context, facility string, province *string, limit, offset int) ([]providers.Clinic, error)

	// ===== Language Support =====
	GetClinicsByLanguage(ctx context.Context, language string, province *string, limit, offset int) ([]providers.Clinic, error)

	// ===== Medical Aid & Payment =====
	GetClinicsAcceptingMedicalAid(ctx context.Context, province *string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsByMedicalAidProvider(ctx context.Context, provider string, province *string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsByPaymentMethod(ctx context.Context, method map[string]any, province *string, limit, offset int) ([]providers.Clinic, error)
	GetClinicsByFeeStructure(ctx context.Context, feeStructure string, province *string, limit, offset int) ([]providers.Clinic, error)

	// ===== Ranking & Discovery =====
	GetTopRatedClinics(ctx context.Context, province *string, minReviews, limit int) ([]providers.Clinic, error)
	GetMostReviewedClinics(ctx context.Context, province *string, limit int) ([]providers.Clinic, error)
	GetRecentlyAddedClinics(ctx context.Context, province *string, limit int) ([]providers.Clinic, error)
	GetRecentlyVerifiedClinics(ctx context.Context, limit int) ([]providers.Clinic, error)

	// ===== Statistics & Analytics =====
	GetClinicStatistics(ctx context.Context, id uuid.UUID) (providers.ClinicStatistics, error)
	GetClinicMetrics(ctx context.Context) (providers.ClinicMetrics, error)
	GetClinicTypeDistribution(ctx context.Context) ([]providers.ClinicTypeDistribution, error)
	GetClinicProvinceDistribution(ctx context.Context) ([]providers.ClinicProvinceDistribution, error)
	GetClinicOwnershipDistribution(ctx context.Context) ([]providers.ClinicOwnershipDistribution, error)

	// ===== Counting & Existence Checks =====
	CountClinics(ctx context.Context, clinicType, province, verificationStatus *string) (int64, error)
	CountVerifiedClinics(ctx context.Context) (int64, error)
	CountClinicsByProvince(ctx context.Context, province string) (int64, error)
	ClinicExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckRegistrationNumberExists(ctx context.Context, registrationNumber string, excludeID *uuid.UUID) (bool, error)
	CheckEmailExists(ctx context.Context, email string, excludeID *uuid.UUID) (bool, error)
	CheckPhoneExists(ctx context.Context, phone string, excludeID *uuid.UUID) (bool, error)

	// ===== Bulk Operations =====
	GetClinicsByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.Clinic, error)
	BulkUpdateVerificationStatus(ctx context.Context, ids []uuid.UUID, status string) error
	BulkVerifyClinics(ctx context.Context, ids []uuid.UUID, verifiedBy uuid.UUID) error

	// ===== Reference Data Lookups =====
	GetClinicByRegistrationNumber(ctx context.Context, registrationNumber string) (providers.Clinic, error)
	GetClinicByEmail(ctx context.Context, email string) (providers.Clinic, error)
	GetClinicByPhone(ctx context.Context, phone string) (providers.Clinic, error)

	// ===== Advanced Search =====
	SearchClinicsAdvanced(ctx context.Context, params providers.ClinicAdvancedSearchParams) ([]providers.Clinic, error)

	// ===== Accreditation Management =====
	GetClinicsWithExpiredAccreditation(ctx context.Context) ([]providers.ClinicAccreditationInfo, error)
	GetClinicsNeedingReaccreditation(ctx context.Context) ([]providers.ClinicAccreditationInfo, error)
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

	// ===== Service Status Management =====
	ActivateService(ctx context.Context, id uuid.UUID) error
	DeactivateService(ctx context.Context, id uuid.UUID) error
	ToggleServiceStatus(ctx context.Context, id uuid.UUID) error

	// ===== Service Details Management =====
	UpdateServiceDetails(ctx context.Context, id uuid.UUID, details providers.ServiceDetails) error
	UpdateServiceEligibility(ctx context.Context, id uuid.UUID, eligibility providers.ServiceEligibility) error
	UpdateServiceCost(ctx context.Context, id uuid.UUID, cost providers.ServiceCost) error
	UpdateServiceAvailability(ctx context.Context, id uuid.UUID, availability providers.ServiceAvailability) error

	// ===== Service Staff Management =====
	UpdateServiceStaff(ctx context.Context, id uuid.UUID, staffIDs []uuid.UUID) error
	AddStaffToService(ctx context.Context, serviceID, staffID uuid.UUID) error
	RemoveStaffFromService(ctx context.Context, serviceID, staffID uuid.UUID) error

	// ===== Service Metrics & Ratings =====
	UpdateServiceRating(ctx context.Context, id uuid.UUID, rating float64, reviewCount int) error
	IncrementServiceReviewCount(ctx context.Context, id uuid.UUID) error
	UpdateServicePopularity(ctx context.Context, id uuid.UUID, score int) error
	IncrementPopularityScore(ctx context.Context, id uuid.UUID) error

	// ===== Querying by Clinic =====
	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetClinicServicesByCategory(ctx context.Context, clinicID uuid.UUID, category string) ([]providers.ClinicService, error)
	GetClinicServicesByStaff(ctx context.Context, clinicID, staffID uuid.UUID) ([]providers.ClinicService, error)

	// ===== Search & Filtering =====
	SearchServices(ctx context.Context, query string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicService, error)
	SearchServicesByCategory(ctx context.Context, category string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicService, error)
	GetServicesByPriceRange(ctx context.Context, clinicID uuid.UUID, minCost, maxCost float64) ([]providers.ClinicService, error)
	GetFreeServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetWalkInServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetAppointmentOnlyServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)

	// ===== Medical Aid Coverage =====
	GetMedicalAidCoveredServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetServicesByMedicalAidCode(ctx context.Context, code map[string]any) ([]providers.ClinicService, error)

	// ===== Age & Eligibility Filtering =====
	GetServicesForAge(ctx context.Context, clinicID uuid.UUID, age int) ([]providers.ClinicService, error)
	GetServicesForGender(ctx context.Context, clinicID uuid.UUID, gender string) ([]providers.ClinicService, error)
	GetPediatricServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetPreventiveServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)

	// ===== Popular & Recommended Services =====
	GetTopRatedServices(ctx context.Context, minReviews int, clinicID *uuid.UUID, limit int) ([]providers.ClinicService, error)
	GetMostPopularServices(ctx context.Context, clinicID uuid.UUID, limit int) ([]providers.ClinicService, error)
	GetRecentlyAddedServices(ctx context.Context, clinicID uuid.UUID, limit int) ([]providers.ClinicService, error)

	// ===== Statistics & Analytics =====
	GetServiceStatistics(ctx context.Context, id uuid.UUID) (providers.ServiceStatistics, error)
	GetClinicServiceMetrics(ctx context.Context, clinicID uuid.UUID) (providers.ServiceMetrics, error)
	GetServiceCategoryDistribution(ctx context.Context, clinicID uuid.UUID) ([]providers.ServiceCategoryDistribution, error)
	GetServicePriceDistribution(ctx context.Context, clinicID uuid.UUID) ([]providers.ServicePriceDistribution, error)

	// ===== Counting & Existence Checks =====
	CountClinicServices(ctx context.Context, clinicID uuid.UUID, isActive *bool) (int64, error)
	CountServicesByCategory(ctx context.Context, clinicID uuid.UUID, category string) (int64, error)
	ServiceExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error)

	// ===== Bulk Operations =====
	GetServicesByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.ClinicService, error)
	BulkActivateServices(ctx context.Context, ids []uuid.UUID) error
	BulkDeactivateServices(ctx context.Context, ids []uuid.UUID) error
	BulkUpdateServiceCategory(ctx context.Context, ids []uuid.UUID, category string) error
	DeactivateClinicServices(ctx context.Context, clinicID uuid.UUID) error

	// ===== Availability & Scheduling =====
	GetServicesAvailableOnDay(ctx context.Context, clinicID uuid.UUID, day string) ([]providers.ClinicService, error)
	GetServicesRequiringFollowUp(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetQuickServices(ctx context.Context, clinicID uuid.UUID, maxDurationMinutes int) ([]providers.ClinicService, error)

	// ===== Comparison & Cross-Clinic Queries =====
	CompareServiceAcrossClinics(ctx context.Context, serviceName string) ([]providers.ServiceComparison, error)
	GetCheapestServiceProviders(ctx context.Context, serviceName string, limit int) ([]providers.ServiceProvider, error)
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
	GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error
	DeleteStaffMember(ctx context.Context, id uuid.UUID) error

	// ===== Professional Information =====
	UpdateStaffProfessionalInfo(ctx context.Context, id uuid.UUID, info providers.StaffProfessionalInfo) error
	UpdateStaffLicenses(ctx context.Context, id uuid.UUID, licenses providers.StaffLicenses) error
	UpdateStaffQualifications(ctx context.Context, id uuid.UUID, qualifications []string) error
	AddStaffQualification(ctx context.Context, id uuid.UUID, qualification string) error

	// ===== Contact Information =====
	UpdateStaffContact(ctx context.Context, id uuid.UUID, contact providers.StaffContact) error
	UpdateStaffProfile(ctx context.Context, id uuid.UUID, profile providers.StaffProfile) error

	// ===== Role & Employment =====
	UpdateStaffRole(ctx context.Context, id uuid.UUID, role, department string) error
	UpdateStaffStatus(ctx context.Context, id uuid.UUID, status string, endDate *time.Time) error
	UpdateStaffEmploymentDates(ctx context.Context, id uuid.UUID, startDate *time.Time, endDate *time.Time) error
	SetPrimaryContact(ctx context.Context, clinicID, staffID uuid.UUID) error
	ActivateStaff(ctx context.Context, id uuid.UUID) error
	DeactivateStaff(ctx context.Context, id uuid.UUID) error
	SetStaffOnLeave(ctx context.Context, id uuid.UUID) error

	// ===== Availability & Scheduling =====
	UpdateStaffAvailability(ctx context.Context, id uuid.UUID, workingHours map[string]any, availableDays []string) error
	UpdatePatientAcceptanceStatus(ctx context.Context, id uuid.UUID, accepting bool) error
	SetAcceptingPatients(ctx context.Context, id uuid.UUID) error
	SetNotAcceptingPatients(ctx context.Context, id uuid.UUID) error

	// ===== Clinic Staff Management =====
	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error)
	GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	GetClinicStaffByRole(ctx context.Context, clinicID uuid.UUID, role string) ([]providers.ClinicStaff, error)
	GetClinicDoctors(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	GetClinicNurses(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	GetClinicPrimaryContact(ctx context.Context, clinicID uuid.UUID) (providers.ClinicStaff, error)

	// ===== Staff Search & Filtering =====
	SearchStaffByName(ctx context.Context, name string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicStaff, error)
	SearchStaffBySpecialization(ctx context.Context, specialization string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicStaff, error)
	GetStaffByDepartment(ctx context.Context, clinicID uuid.UUID, department string) ([]providers.ClinicStaff, error)

	// ===== Staff Availability Queries =====
	GetStaffAvailableOnDay(ctx context.Context, clinicID uuid.UUID, day string) ([]providers.ClinicStaff, error)
	GetStaffWorkingHours(ctx context.Context, id uuid.UUID) (providers.StaffWorkingHours, error)

	// ===== Licensing & Credentials =====
	GetStaffByHPCSNumber(ctx context.Context, hpcsNumber string) (providers.ClinicStaff, error)
	CheckHPCSNumberExists(ctx context.Context, hpcsNumber string, excludeID *uuid.UUID) (bool, error)
	GetStaffWithExpiredLicenses(ctx context.Context) ([]providers.ClinicStaff, error)

	GetStaffNeedingCredentialRenewal(ctx context.Context) ([]providers.StaffCredentialRenewal, error)
	// ===== Transfer & Reassignment =====
	TransferStaffToClinic(ctx context.Context, staffID, newClinicID uuid.UUID) error
	GetStaffTransferHistory(ctx context.Context, userID uuid.UUID) ([]providers.ClinicStaff, error)

	// ===== Statistics & Analytics =====
	GetStaffStatistics(ctx context.Context, id uuid.UUID) (providers.StaffStatistics, error)
	GetClinicStaffMetrics(ctx context.Context, clinicID uuid.UUID) (providers.StaffMetrics, error)
	GetStaffRoleDistribution(ctx context.Context, clinicID uuid.UUID) ([]providers.StaffRoleDistribution, error)
	GetStaffByExperience(ctx context.Context, clinicID uuid.UUID, minYears int) ([]providers.ClinicStaff, error)
	GetStaffDemographics(ctx context.Context, clinicID uuid.UUID) (providers.StaffDemographics, error)

	// ===== Counting & Existence Checks =====
	CountClinicStaff(ctx context.Context, clinicID uuid.UUID, employmentStatus *string) (int64, error)
	CountStaffByRole(ctx context.Context, clinicID uuid.UUID, role string) (int64, error)
	StaffExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckStaffEmailExists(ctx context.Context, email string, excludeID *uuid.UUID) (bool, error)
	CheckUserStaffExists(ctx context.Context, userID uuid.UUID) (bool, error)

	// ===== Bulk Operations =====
	GetStaffByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.ClinicStaff, error)
	BulkUpdateStaffStatus(ctx context.Context, ids []uuid.UUID, status string) error
	BulkSetAcceptingPatients(ctx context.Context, ids []uuid.UUID, accepting bool) error
	DeactivateClinicStaff(ctx context.Context, clinicID uuid.UUID) error

	// ===== Language & Communication =====
	GetStaffByLanguage(ctx context.Context, clinicID uuid.UUID, language string) ([]providers.ClinicStaff, error)
	GetMultilingualStaff(ctx context.Context, clinicID uuid.UUID, minLanguages []string) ([]providers.StaffLanguageInfo, error)

	// ===== Reporting & Compliance =====
	GetStaffWithoutHPCSNumber(ctx context.Context) ([]providers.ClinicStaff, error)
	GetStaffWithIncompleteProfiles(ctx context.Context) ([]providers.ClinicStaff, error)
	GetStaffHiredBetweenDates(ctx context.Context, startDate, startDate2 time.Time) ([]providers.ClinicStaff, error)
	GetStaffTerminatedBetweenDates(ctx context.Context, endDate1, endDate time.Time) ([]providers.ClinicStaff, error)
}

// ============================================
// CREDENTIAL REPOSITORY
// Maps to: professional_credentials.sql
// Domain: Professional Licensing & Certification Management
// ============================================

type CredentialRepository interface {
	// ===== Core CRUD Operations =====
	CreateCredential(ctx context.Context, credential providers.ProfessionalCredential) (providers.ProfessionalCredential, error)
	GetCredentialByID(ctx context.Context, id uuid.UUID) (providers.ProfessionalCredential, error)
	UpdateCredential(ctx context.Context, credential providers.ProfessionalCredential) error
	DeleteCredential(ctx context.Context, id uuid.UUID) error

	// ===== Verification & Status Management =====
	VerifyCredential(ctx context.Context, id, verifiedBy uuid.UUID, notes *string) error
	RejectCredential(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	RevokeCredential(ctx context.Context, id uuid.UUID, notes string) error
	MarkCredentialExpired(ctx context.Context, id uuid.UUID) error
	UpdateCredentialStatus(ctx context.Context, id uuid.UUID, status string) error
	RenewCredential(ctx context.Context, id uuid.UUID, expiryDate time.Time) error

	// ===== Credential Details Management =====
	UpdateCredentialNumber(ctx context.Context, id uuid.UUID, credentialNumber string) error
	UpdateCredentialExpiry(ctx context.Context, id uuid.UUID, expiryDate time.Time) error
	UpdateCredentialDocument(ctx context.Context, id uuid.UUID, documentURL string) error
	UpdateCredentialNotes(ctx context.Context, id uuid.UUID, notes string) error
	UpdateCredentialDates(ctx context.Context, id uuid.UUID, issueDate, expiryDate time.Time) error

	// ===== Querying by Staff Member =====
	GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	GetVerifiedStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	GetActiveStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	GetStaffCredentialsByType(ctx context.Context, staffID uuid.UUID, credentialType string) ([]providers.ProfessionalCredential, error)

	// ===== Credential Type Queries =====
	GetCredentialsByType(ctx context.Context, credentialType string) ([]providers.CredentialWithStaff, error)
	GetLicenseCredentials(ctx context.Context, clinicID *uuid.UUID) ([]providers.CredentialWithStaff, error)
	GetSpecializationCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error)
	GetDegreeCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error)
	GetCertificationCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error)

	// ===== Verification Workflows =====
	GetPendingCredentialVerifications(ctx context.Context) ([]providers.CredentialWithStaff, error)
	GetPendingCredentialsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.CredentialWithStaff, error)
	GetVerifiedCredentialsByDateRange(ctx context.Context, startDate, endDate time.Time) ([]providers.CredentialWithStaff, error)

	// ===== Expiration Management =====
	GetExpiringCredentials(ctx context.Context, daysUntilExpiry int) ([]providers.CredentialWithStaff, error)
	GetExpiredCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error)
	GetClinicExpiredCredentials(ctx context.Context, clinicID uuid.UUID) ([]providers.CredentialWithStaff, error)
	AutoExpireCredentials(ctx context.Context) error

	// ===== Issuing Authority Queries =====
	GetCredentialsByAuthority(ctx context.Context, issuingAuthority string) ([]providers.CredentialWithStaff, error)
	GetCredentialsByAuthorityAndType(ctx context.Context, issuingAuthority, credentialType string) ([]providers.CredentialWithStaff, error)

	// ===== Statistics & Analytics =====
	GetCredentialStatistics(ctx context.Context, staffID uuid.UUID) (providers.CredentialStatistics, error)
	GetClinicCredentialMetrics(ctx context.Context, clinicID uuid.UUID) (providers.ClinicCredentialMetrics, error)
	GetCredentialTypeDistribution(ctx context.Context, staffID uuid.UUID) ([]providers.CredentialTypeDistribution, error)
	GetCredentialStatusDistribution(ctx context.Context, staffID uuid.UUID) ([]providers.CredentialStatusDistribution, error)
	GetSystemCredentialMetrics(ctx context.Context) (providers.SystemCredentialMetrics, error)

	// ===== Counting & Existence Checks =====
	CountStaffCredentials(ctx context.Context, staffID uuid.UUID, status *string) (int64, error)
	CountCredentialsByType(ctx context.Context, staffID uuid.UUID, credentialType string) (int64, error)
	CredentialExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckCredentialNumberExists(ctx context.Context, credentialNumber, issuingAuthority string, excludeID *uuid.UUID) (bool, error)
	HasVerifiedCredentialOfType(ctx context.Context, staffID uuid.UUID, credentialType string) (bool, error)

	// ===== Bulk Operations =====
	GetCredentialsByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.ProfessionalCredential, error)
	BulkVerifyCredentials(ctx context.Context, ids []uuid.UUID, verifiedBy uuid.UUID) error
	BulkRejectCredentials(ctx context.Context, ids []uuid.UUID, verifiedBy uuid.UUID, notes string) error
	BulkUpdateCredentialStatus(ctx context.Context, ids []uuid.UUID, status string) error
	DeleteStaffCredentials(ctx context.Context, staffID uuid.UUID) error

	// ===== Compliance & Reporting =====
	GetStaffWithoutRequiredCredentials(ctx context.Context) ([]providers.ClinicStaff, error)
	GetVerificationBacklog(ctx context.Context) ([]providers.VerificationBacklog, error)
	GetVerifierWorkload(ctx context.Context, startDate, endDate time.Time) ([]providers.VerifierWorkload, error)
	GetCredentialsByDateRange(ctx context.Context, startDate, endDate time.Time) ([]providers.CredentialWithStaff, error)
	GetRevokedCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error)
	GetCredentialRenewalHistory(ctx context.Context, staffID uuid.UUID, credentialType string) ([]providers.ProfessionalCredential, error)
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
