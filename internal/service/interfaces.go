package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
)

// AuthService handles auth operations
type AuthService interface {
	Register(ctx context.Context, email, phone, password, role string) (core.User, error)
	RegisterInvitedStaff(ctx context.Context, token, email, password, phone string) (core.User, error)
	Login(ctx context.Context, identifier, password, ipAddress, userAgent string) (string, time.Time, core.User, error)
	Logout(ctx context.Context, tokenString string, userID uuid.UUID) error
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
	RefreshToken(ctx context.Context, tokenString string, ipAddress, userAgent string) (string, time.Time, core.User, error)
	VerifyEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, identifier string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ResendVerificationEmail(ctx context.Context, email string) error
	UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error
	UpdateUserPrimaryClinic(ctx context.Context, userID, clinicID uuid.UUID) error
	CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error
	GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error)
	GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error)
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
	CanSendNotification(ctx context.Context, userID uuid.UUID, notificationType, channel string) (bool, error)
}

// AuditService defines the interface for audit logging and reporting operations
type AuditService interface {
	LogUserActivity(ctx context.Context, activity core.UserActivity) error
	GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error)
	LogDataAccess(ctx context.Context, access core.DataAccessLog) error
}

// ConsentService defines the interface for consent management operations
type ConsentService interface {
	GetPrivacyConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error)
	CreatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error)
	UpdatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) error
}

// PatientService handles patient operations
type PatientService interface {
	CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	GetPatientProfile(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error)
	UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error
	DeletePatientProfile(ctx context.Context, id uuid.UUID) error
	DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error
	SearchPatients(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error)
	GetDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error)
	GetPatientByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
}

// SurgeryService handles patient surgery operations
type SurgeryService interface {
	AddPatientSurgery(ctx context.Context, surgery patients.PatientSurgery) (patients.PatientSurgery, error)
	GetPatientSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
	GetRecentSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error)
	UpdatePatientSurgery(ctx context.Context, surgery patients.PatientSurgery) error
	DeletePatientSurgery(ctx context.Context, id uuid.UUID) error
}

// MedicalInfoService handles patient medical info operations
type MedicalInfoService interface {
	CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) (patients.PatientMedicalInfo, error)
	GetMedicalInfoByID(ctx context.Context, id uuid.UUID) (patients.PatientMedicalInfo, error)
	GetMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error)
	UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error
	DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error
}

// ImmunizationService handles patient immunization operations
type ImmunizationService interface {
	AddPatientImmunization(ctx context.Context, immunization patients.PatientImmunization) (patients.PatientImmunization, error)
	GetPatientImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error)
	UpdatePatientImmunization(ctx context.Context, immunization patients.PatientImmunization) error
	DeletePatientImmunization(ctx context.Context, id uuid.UUID) error
}

// FamilyHistoryService handles patient family history operations
type FamilyHistoryService interface {
	AddFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) (patients.PatientFamilyHistory, error)
	GetPatientFamilyHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error)
	UpdateFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) error
	DeleteFamilyHistory(ctx context.Context, id uuid.UUID) error
}

// MedicationService handles patient medication operations
type MedicationService interface {
	AddPatientMedication(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error)
	GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error)
	GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error)
	UpdatePatientMedication(ctx context.Context, medication patients.PatientMedication) error
	DeletePatientMedication(ctx context.Context, id uuid.UUID) error
}

// DependentService handles patient dependent operations
type DependentService interface {
	AddPatientDependent(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error)
	GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
	GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error)
	UpdatePatientDependent(ctx context.Context, dependent patients.PatientDependent) error
	DeletePatientDependent(ctx context.Context, id uuid.UUID) error
}

// DependentHealthRecordService handles dependent health record operations
type DependentHealthRecordService interface {
	AddDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) (patients.DependentHealthRecord, error)
	GetDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error)
	UpdateDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) error
	DeleteDependentHealthRecord(ctx context.Context, id uuid.UUID) error
}

// ConditionService handles patient condition operations
type ConditionService interface {
	AddPatientCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error)
	GetPatientConditions(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientCondition, error)
	GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error)
	UpdatePatientCondition(ctx context.Context, condition patients.PatientCondition) error
	DeletePatientCondition(ctx context.Context, id uuid.UUID) error
}

// AllergyService handles patient allergy operations
type AllergyService interface {
	AddPatientAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error)
	GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error)
	UpdatePatientAllergy(ctx context.Context, allergy patients.PatientAllergy) error
	DeletePatientAllergy(ctx context.Context, id uuid.UUID) error
}

// EmergencyContactService handles emergency contact operations
type EmergencyContactService interface {
	AddEmergencyContact(ctx context.Context, contact patients.EmergencyContact) (patients.EmergencyContact, error)
	GetPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) ([]patients.EmergencyContact, error)
	GetPrimaryEmergencyContact(ctx context.Context, patientID uuid.UUID) (patients.EmergencyContact, error)
	UpdateEmergencyContact(ctx context.Context, contact patients.EmergencyContact) error
	DeleteEmergencyContact(ctx context.Context, id uuid.UUID) error
}

// ClinicService handles clinic operations
type ClinicService interface {
	RegisterClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error)
	GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	GetClinicByUserID(ctx context.Context, userID uuid.UUID) (*providers.Clinic, error)
	UpdateClinic(ctx context.Context, clinic providers.Clinic) error
	DeleteClinic(ctx context.Context, id uuid.UUID) error

	VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error
	DeactivateClinic(ctx context.Context, id uuid.UUID) error
	ReactivateClinic(ctx context.Context, id uuid.UUID) error

	SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error)
	GetClinics(ctx context.Context) ([]providers.Clinic, error)
	GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error)
	GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicWithOwner, error)
	UpdateClinicOwner(ctx context.Context, clinicID, newOwnerUserID uuid.UUID, updatedBy uuid.UUID) error
	GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicVerification, error)
}

type StaffService interface {
	CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error)
	GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error)
	GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error)
	GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error
	DeleteStaffMember(ctx context.Context, id uuid.UUID) error

	GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error)
	GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	StaffExists(ctx context.Context, id uuid.UUID) (bool, error)
	CreateStaffInvitation(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error)
	GetStaffInvitationByToken(ctx context.Context, token string) (*providers.StaffInvitationDetails, error)
	AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) (providers.ClinicStaff, error)
	DeclineStaffInvitation(ctx context.Context, token string) error
	GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	GetStaffInvitationsByEmail(ctx context.Context, email string) ([]providers.StaffInvitationDetails, error)
	CancelStaffInvitation(ctx context.Context, token string, cancelledBy uuid.UUID) error
	ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID, resentBy uuid.UUID) (string, error)
	GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error)
	UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions providers.StaffPermissions, updatedBy uuid.UUID) error
	ExpireStaffInvitations(ctx context.Context) error
}

// ServiceCatalogService handles clinic service operations
type ServiceCatalogService interface {
	CreateClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error)
	GetServiceByID(ctx context.Context, id uuid.UUID) (providers.ClinicService, error)
	UpdateClinicService(ctx context.Context, service providers.ClinicService) error
	DeleteClinicService(ctx context.Context, id uuid.UUID) error

	GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error)
	ServiceExists(ctx context.Context, id uuid.UUID) (bool, error)
	CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error)
}

// CredentialService handles professional credential operations
type CredentialService interface {
	CreateCredential(ctx context.Context, credential providers.ProfessionalCredential) (providers.ProfessionalCredential, error)
	GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error)
	DeleteCredential(ctx context.Context, id uuid.UUID) error
}

type SystemAdminService interface {
	CreateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error)
	GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error)
}

type AppointmentService interface {
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
}

// SymptomCheckerService defines all operations for the symptom checker workflow.
type SymptomCheckerService interface {
	// ── Patient-facing ──────────────────────────────────────────────────────

	// SubmitSession validates input, calls the AI for triage, persists and
	// returns the completed session. This is the primary entry point.
	SubmitSession(ctx context.Context, session telemedicine.SymptomCheckerSession) (telemedicine.SymptomCheckerSession, error)

	// GetSessionByID retrieves a full session by ID.
	GetSessionByID(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error)

	// GetPatientSessions returns a paginated summary list of sessions for a patient.
	GetPatientSessions(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.SymptomSessionSummary, error)

	// GetDependentSessions returns all sessions filed for a specific dependent
	// of a patient. Validates dependent ownership before returning data.
	GetDependentSessions(ctx context.Context, patientID, dependentID uuid.UUID) ([]telemedicine.DependentSessionSummary, error)

	// GetLatestEligibleSession returns the most recent telemedicine-eligible
	// session (completed, within 24 hours, recommended_action=telemedicine).
	// This is the preflight check the patient must pass before seeing the
	// provider list. Returns domain.ErrNotFound when none qualifies.
	GetLatestEligibleSession(ctx context.Context, patientID uuid.UUID) (telemedicine.EligibleSession, error)

	// GetSessionWithPatientContext returns the rich provider-facing view of a
	// session, joined with patient demographics and medical summary.
	// Called when a provider accepts a consultation.
	GetSessionWithPatientContext(ctx context.Context, sessionID uuid.UUID) (telemedicine.SessionWithPatientContext, error)

	// ── Lifecycle mutations ─────────────────────────────────────────────────

	// AbandonSession marks a completed session as abandoned.
	// Called when a patient exits the flow without proceeding to a consultation.
	AbandonSession(ctx context.Context, sessionID, patientID uuid.UUID) error

	// MarkSessionConverted transitions a session to converted_to_consult.
	// Called by the consultation service once a consultation is created.
	MarkSessionConverted(ctx context.Context, sessionID uuid.UUID) error

	// ── Admin / analytics ──────────────────────────────────────────────────

	// GetSessionsByTriageLevel returns paginated sessions filtered by triage
	// level and creation date range. Used in the admin dashboard.
	GetSessionsByTriageLevel(ctx context.Context, triageLevel telemedicine.TriageLevel, from, to time.Time, limit, offset int) ([]telemedicine.AdminSessionSummary, error)

	// CountSessionsByOutcome returns per-action session counts within a time
	// window. Used for analytics.
	CountSessionsByOutcome(ctx context.Context, from, to time.Time) ([]telemedicine.SessionOutcomeCount, error)
}

// ConsultationService defines all operations for the consultation lifecycle.
type ConsultationService interface {
	// ── Patient-facing ──────────────────────────────────────────────────────

	// RequestConsultation opens a new consultation from a completed eligible symptom session.
	// Enforces one-active-consultation-per-patient.
	RequestConsultation(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error)

	// GetConsultationByID retrieves a full consultation by primary key.
	GetConsultationByID(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error)

	// GetConsultationWithDetails returns the hydrated view used to render the chat screen.
	GetConsultationWithDetails(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationWithDetails, error)

	// GetPatientConsultations returns paginated consultation history for a patient.
	GetPatientConsultations(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.PatientConsultationSummary, error)

	// GetPatientActiveConsultation returns the patient's current open consultation.
	// Returns domain.ErrNotFound when none exists.
	GetPatientActiveConsultation(ctx context.Context, patientID uuid.UUID) (telemedicine.ActiveConsultationCheck, error)

	// CancelConsultation cancels a pending or accepted consultation.
	CancelConsultation(ctx context.Context, id uuid.UUID, cancelledBy uuid.UUID) (telemedicine.Consultation, error)

	// SubmitPatientRating records a star rating and optional feedback on a closed consultation.
	SubmitPatientRating(ctx context.Context, id uuid.UUID, patientID uuid.UUID, rating int, feedback *string) error

	// ── Provider-facing ─────────────────────────────────────────────────────

	// AcceptConsultation assigns a provider, increments their active count, and applies fee override.
	AcceptConsultation(ctx context.Context, id uuid.UUID, providerStaffID uuid.UUID, clinicID uuid.UUID) (telemedicine.Consultation, error)

	// StartConsultation transitions an accepted consultation to in_progress.
	StartConsultation(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error)

	// CompleteConsultation closes an in_progress consultation and decrements provider count.
	CompleteConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error)

	// EscalateConsultation moves an active consultation to escalated.
	EscalateConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error)

	// DeclineConsultation moves a pending consultation to declined so the patient can re-select.
	DeclineConsultation(ctx context.Context, id uuid.UUID) error

	// MarkNoShow marks an accepted consultation as no_show.
	MarkNoShow(ctx context.Context, id uuid.UUID) error

	// GetProviderActiveConsultations returns all open consultations for a provider.
	GetProviderActiveConsultations(ctx context.Context, providerStaffID uuid.UUID) ([]telemedicine.ProviderActiveConsultation, error)

	// GetWaitingRoom returns all pending_acceptance consultations for the provider waiting room.
	GetWaitingRoom(ctx context.Context) ([]telemedicine.WaitingRoomEntry, error)

	// GetProviderConsultationHistory returns paginated closed consultations for a provider.
	GetProviderConsultationHistory(ctx context.Context, providerStaffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderConsultationHistoryEntry, error)

	// ── Billing & admin ─────────────────────────────────────────────────────

	// UpdatePaymentStatus updates the payment state and records a payment reference.
	UpdatePaymentStatus(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error

	// UpdateConsultationChannel changes the channel (e.g. chat → video).
	UpdateConsultationChannel(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error

	// LinkFollowUpAppointment associates a follow-up booking with a closed consultation.
	LinkFollowUpAppointment(ctx context.Context, id uuid.UUID, appointmentID uuid.UUID) error
}

// ConsultationMessagesService defines all operations for the chat message thread.
type ConsultationMessagesService interface {
	// ── Write ───────────────────────────────────────────────────────────────

	// SendMessage validates and persists a new message from a patient or provider.
	SendMessage(ctx context.Context, msg telemedicine.ConsultationMessage) (telemedicine.ConsultationMessage, error)

	// DeleteMessage soft-deletes a message. Only the original sender may delete their own messages.
	DeleteMessage(ctx context.Context, id uuid.UUID, requestingUserID uuid.UUID) error

	// InsertSystemEvent emits a system-generated event into a consultation's message thread.
	InsertSystemEvent(ctx context.Context, consultationID uuid.UUID, systemUserID uuid.UUID, label string, metadata map[string]interface{}) (telemedicine.ConsultationMessage, error)

	// ── Read ────────────────────────────────────────────────────────────────

	// GetConsultationMessages returns a paginated message thread for initial chat load.
	GetConsultationMessages(ctx context.Context, consultationID uuid.UUID, limit, offset int) ([]telemedicine.ConsultationMessage, error)

	// GetMessagesAfterCursor returns all messages newer than a timestamp for polling/WebSocket catch-up.
	GetMessagesAfterCursor(ctx context.Context, consultationID uuid.UUID, cursor time.Time) ([]telemedicine.MessageAfterCursor, error)

	// GetLastMessage returns the most recent message preview for consultation list cards.
	GetLastMessage(ctx context.Context, consultationID uuid.UUID) (telemedicine.LastMessagePreview, error)

	// GetSystemEvents returns all system-generated events for the call log panel.
	GetSystemEvents(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.SystemEvent, error)

	// GetConsultationAttachments returns all shared files for the attachment panel.
	GetConsultationAttachments(ctx context.Context, consultationID uuid.UUID) ([]telemedicine.AttachmentEntry, error)

	// ── Read receipts ───────────────────────────────────────────────────────

	// MarkMessageRead marks a single message as read.
	MarkMessageRead(ctx context.Context, id uuid.UUID) error

	// MarkAllProviderMessagesRead marks all unread provider messages as read (called by patient).
	MarkAllProviderMessagesRead(ctx context.Context, consultationID uuid.UUID) error

	// MarkAllPatientMessagesRead marks all unread patient messages as read (called by provider).
	MarkAllPatientMessagesRead(ctx context.Context, consultationID uuid.UUID) error

	// CountUnreadMessages returns the unread badge count for a given sender role.
	CountUnreadMessages(ctx context.Context, consultationID uuid.UUID, senderRole telemedicine.SenderRole) (telemedicine.UnreadCount, error)
}

// ConsultationNotesService defines all operations for the provider SOAP clinical note.
type ConsultationNotesService interface {
	// ── Write ───────────────────────────────────────────────────────────────

	// CreateNote opens a draft note for a consultation. Only one note per consultation is allowed.
	CreateNote(ctx context.Context, consultationID uuid.UUID, authoredByStaffID uuid.UUID) (telemedicine.ConsultationNote, error)

	// UpdateNote auto-saves SOAP fields as the provider types.
	// Finalised notes cannot be updated.
	UpdateNote(ctx context.Context, id uuid.UUID, update telemedicine.ConsultationNote, requestingStaffID uuid.UUID) (telemedicine.ConsultationNote, error)

	// FinaliseNote locks a note by its note ID. Called from the note panel when "End Consultation" is clicked.
	FinaliseNote(ctx context.Context, id uuid.UUID, requestingStaffID uuid.UUID) (telemedicine.ConsultationNote, error)

	// FinaliseNoteByConsultation locks the note for a consultation by consultation ID.
	// More natural to call from the consultation service when completing a consultation.
	FinaliseNoteByConsultation(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error)

	// ─── Read Operations ──────────────────────────────────────────────────────────

	// GetNoteByID retrieves a full note by its primary key.
	GetNoteByID(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error)

	// GetNoteByConsultationID retrieves the note for a given consultation.
	GetNoteByConsultationID(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error)

	// GetNoteWithProviderInfo returns the note joined with the authoring provider's profile.
	// Used in patient records and admin audits.
	GetNoteWithProviderInfo(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNoteWithProviderInfo, error)

	// ─── History ─────────────────────────────────────────────────────────────────

	// GetProviderNoteHistory returns paginated finalised notes written by a provider.
	GetProviderNoteHistory(ctx context.Context, staffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderNoteHistoryEntry, error)

	// GetPatientNoteHistory returns all finalised notes across a patient's consultations.
	GetPatientNoteHistory(ctx context.Context, patientID uuid.UUID) ([]telemedicine.PatientNoteHistoryEntry, error)
}

// ProviderAvailabilityService defines all operations for provider presence management.
type ProviderAvailabilityService interface {
	// ── Provider self-management ────────────────────────────────────────────

	// GoOnline marks the provider as online and records their shift start.
	GoOnline(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error)

	// GoOffline marks the provider as offline, clears accepting state, and nulls shift_start.
	GoOffline(ctx context.Context, staffID uuid.UUID) error

	// SetAccepting toggles the provider's accepting state and optionally updates fee override
	// and estimated wait minutes. Provider must be online to accept.
	SetAccepting(ctx context.Context, staffID uuid.UUID, accepting bool, feeOverride *float64, waitMinutes *int) (telemedicine.ProviderAvailability, error)

	// UpdateStatus sets the provider's status enum and optional status message.
	UpdateStatus(ctx context.Context, staffID uuid.UUID, status telemedicine.ProviderAvailabilityStatus, message *string) error

	// UpdateHeartbeat records last_seen_at to keep the provider's presence alive.
	UpdateHeartbeat(ctx context.Context, staffID uuid.UUID) error

	// UpdateWaitTime sets the estimated wait minutes displayed to patients.
	UpdateWaitTime(ctx context.Context, staffID uuid.UUID, minutes int) error

	// GetAvailabilityByStaffID fetches the full availability record for a provider.
	GetAvailabilityByStaffID(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error)

	// ── Patient-facing ──────────────────────────────────────────────────────

	// GetAvailableProviders returns all currently accepting providers for the patient list.
	GetAvailableProviders(ctx context.Context, clinicID *uuid.UUID) ([]telemedicine.AvailableProvider, error)

	// GetAvailableProvidersBySpecialization filters the available provider list by specialization.
	GetAvailableProvidersBySpecialization(ctx context.Context, specialization string) ([]telemedicine.AvailableProviderBySpecialization, error)

	// ── Background job ──────────────────────────────────────────────────────

	// GetStaleProviders returns providers whose heartbeat is older than 2 minutes.
	GetStaleProviders(ctx context.Context) ([]telemedicine.StaleProvider, error)

	// SetStaleProvidersOffline bulk-marks heartbeat-stale providers as offline.
	SetStaleProvidersOffline(ctx context.Context) error
}

// TokenClaims represents JWT token claims for health project
type TokenClaims struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	Email  string    `json:"email"`
}
