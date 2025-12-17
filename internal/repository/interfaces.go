// Package repository defines repository interfaces
package repository

import (
	"context"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"

	"github.com/jackc/pgx/v5"
)

// UserRepository defines methods for user data access
type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User, passwordHash string) (domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (domain.User, string, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	GetUserByPhone(ctx context.Context, phone string) (domain.User, error)
	UpdateUser(ctx context.Context, user domain.User) error
	UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	VerifyUser(ctx context.Context, id uuid.UUID) error
	DeactivateUser(ctx context.Context, id uuid.UUID) error
	ListUsers(ctx context.Context, role string, limit, offset int) ([]domain.User, error)
	CountUsers(ctx context.Context, role string) (int64, error)
}

// PatientRepository defines methods for patient profile data access
type PatientRepository interface {
	CreatePatientProfile(ctx context.Context, profile domain.PatientProfile) (domain.PatientProfile, error)
	GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (domain.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (domain.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile domain.PatientProfile) error
	SearchPatients(ctx context.Context, query string, province string, limit, offset int) ([]domain.PatientProfile, error)

	// Medical Information
	CreateMedicalInfo(ctx context.Context, info domain.PatientMedicalInfo) error
	GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (domain.PatientMedicalInfo, error)
	UpdateMedicalInfo(ctx context.Context, info domain.PatientMedicalInfo) error

	// Allergies
	AddAllergy(ctx context.Context, allergy domain.PatientAllergy) (domain.PatientAllergy, error)
	GetAllergies(ctx context.Context, patientID uuid.UUID) ([]domain.PatientAllergy, error)
	UpdateAllergy(ctx context.Context, allergy domain.PatientAllergy) error
	DeleteAllergy(ctx context.Context, id uuid.UUID) error

	// Medications
	AddMedication(ctx context.Context, med domain.PatientMedication) (domain.PatientMedication, error)
	GetMedications(ctx context.Context, patientID uuid.UUID, status string) ([]domain.PatientMedication, error)
	UpdateMedication(ctx context.Context, med domain.PatientMedication) error

	// Conditions
	AddCondition(ctx context.Context, condition domain.PatientCondition) (domain.PatientCondition, error)
	GetConditions(ctx context.Context, patientID uuid.UUID, status string) ([]domain.PatientCondition, error)
	UpdateCondition(ctx context.Context, condition domain.PatientCondition) error

	// Immunizations
	AddImmunization(ctx context.Context, imm domain.PatientImmunization) (domain.PatientImmunization, error)
	GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]domain.PatientImmunization, error)
	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]domain.PatientImmunization, error)
}

// ClinicRepository defines methods for clinic data access
type ClinicRepository interface {
	CreateClinic(ctx context.Context, clinic domain.Clinic) (domain.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (domain.Clinic, error)
	UpdateClinic(ctx context.Context, clinic domain.Clinic) error
	VerifyClinic(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error
	ListClinics(ctx context.Context, filters domain.ClinicFilters, limit, offset int) ([]domain.Clinic, error)
	SearchClinics(ctx context.Context, query string, province string, city string, limit, offset int) ([]domain.Clinic, error)
	SearchClinicsByLocation(ctx context.Context, lat, lng float64, radiusKm float64) ([]domain.Clinic, error)

	// Clinic Services
	AddClinicService(ctx context.Context, service domain.ClinicService) (domain.ClinicService, error)
	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]domain.ClinicService, error)
	UpdateClinicService(ctx context.Context, service domain.ClinicService) error
	DeactivateClinicService(ctx context.Context, id uuid.UUID) error
}

// StaffRepository defines methods for clinic staff data access
type StaffRepository interface {
	CreateStaffMember(ctx context.Context, staff domain.ClinicStaff) (domain.ClinicStaff, error)
	GetStaffByID(ctx context.Context, id uuid.UUID) (domain.ClinicStaff, error)
	GetStaffByUserID(ctx context.Context, userID uuid.UUID) (domain.ClinicStaff, error)
	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role string) ([]domain.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff domain.ClinicStaff) error
	UpdateStaffStatus(ctx context.Context, id uuid.UUID, status string) error

	// Credentials
	AddCredential(ctx context.Context, cred domain.ProfessionalCredential) (domain.ProfessionalCredential, error)
	GetCredentials(ctx context.Context, staffID uuid.UUID) ([]domain.ProfessionalCredential, error)
	VerifyCredential(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID) error
	UpdateCredential(ctx context.Context, cred domain.ProfessionalCredential) error
}

// SessionRepository defines methods for session management
type SessionRepository interface {
	CreateSession(ctx context.Context, session domain.UserSession) (domain.UserSession, error)
	GetSession(ctx context.Context, sessionToken string) (domain.UserSession, error)
	DeleteSession(ctx context.Context, sessionToken string) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context) error
}

// ConsentRepository defines methods for privacy consent management (POPIA compliance)
type ConsentRepository interface {
	CreateConsent(ctx context.Context, consent domain.PrivacyConsent) (domain.PrivacyConsent, error)
	GetConsent(ctx context.Context, userID uuid.UUID) (domain.PrivacyConsent, error)
	UpdateConsent(ctx context.Context, consent domain.PrivacyConsent) error
	WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error
}

// AuditRepository defines methods for audit logging (POPIA compliance)
type AuditRepository interface {
	LogActivity(ctx context.Context, activity domain.UserActivity) error
	GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]domain.UserActivity, error)

	LogDataAccess(ctx context.Context, access domain.DataAccessLog) error
	GetDataAccessLogs(ctx context.Context, accessedUserID uuid.UUID, limit, offset int) ([]domain.DataAccessLog, error)
}

// NotificationRepository defines methods for notification preferences
type NotificationRepository interface {
	CreatePreferences(ctx context.Context, prefs domain.NotificationPreferences) (domain.NotificationPreferences, error)
	GetPreferences(ctx context.Context, userID uuid.UUID) (domain.NotificationPreferences, error)
	UpdatePreferences(ctx context.Context, prefs domain.NotificationPreferences) error
}

// TxManager handles database transactions
type TxManager interface {
	WithTransaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error
}
