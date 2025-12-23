// Package domain
package domain

import (
	"time"

	"github.com/docker/distribution/uuid"
)

// User represents a system user with role-based access
type User struct {
	ID                   uuid.UUID  `json:"id"`
	Email                *string    `json:"email,omitempty"`
	Phone                *string    `json:"phone,omitempty"`
	Role                 string     `json:"role"`   // patient, caregiver, provider_staff, clinic_admin, system_admin, ngo_partner
	Status               string     `json:"status"` // active, inactive, pending_verification, suspended
	IsVerified           bool       `json:"is_verified"`
	VerificationToken    *string    `json:"-"`
	VerificationExpires  *time.Time `json:"-"`
	ResetPasswordToken   *string    `json:"-"`
	ResetPasswordExpires *time.Time `json:"-"`
	LastLogin            *time.Time `json:"last_login,omitempty"`
	LoginCount           int        `json:"login_count"`
	IsSMSOnly            bool       `json:"is_sms_only"`
	SMSConsentGiven      bool       `json:"sms_consent_given"`
	POPIAConsentGiven    bool       `json:"popia_consent_given"`
	EmailConsentGiven    bool       `json:"email_consent_given"`
	ConsentDate          *time.Time `json:"consent_date,omitempty"`
	ProfileCompletionPct int        `json:"profile_completion_percentage"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// PatientProfile represents detailed patient information
type PatientProfile struct {
	ID                           uuid.UUID  `json:"id"`
	UserID                       uuid.UUID  `json:"user_id"`
	FirstName                    string     `json:"first_name"`
	LastName                     string     `json:"last_name"`
	PreferredName                *string    `json:"preferred_name,omitempty"`
	DateOfBirth                  *time.Time `json:"date_of_birth,omitempty"`
	Gender                       *string    `json:"gender,omitempty"`
	PreferredGenderPronouns      *string    `json:"preferred_gender_pronouns,omitempty"`
	PrimaryAddress               *string    `json:"primary_address,omitempty"`
	City                         *string    `json:"city,omitempty"`
	Province                     *string    `json:"province,omitempty"`
	PostalCode                   *string    `json:"postal_code,omitempty"`
	Country                      string     `json:"country"`
	LanguagePreferences          []string   `json:"language_preferences"`
	HomeLanguage                 *string    `json:"home_language,omitempty"`
	RequiresInterpreter          bool       `json:"requires_interpreter"`
	PreferredCommunicationMethod string     `json:"preferred_communication_method"` // sms, email, whatsapp, call
	MedicalAidNumber             *string    `json:"medical_aid_number,omitempty"`
	MedicalAidProvider           *string    `json:"medical_aid_provider,omitempty"`
	HasMedicalAid                bool       `json:"has_medical_aid"`
	NationalIDNumber             *string    `json:"national_id_number,omitempty"`
	EmploymentStatus             *string    `json:"employment_status,omitempty"`
	EducationLevel               *string    `json:"education_level,omitempty"`
	HouseholdIncomeRange         *string    `json:"household_income_range,omitempty"`
	ProfilePictureURL            *string    `json:"profile_picture_url,omitempty"`
	Timezone                     string     `json:"timezone"`
	LastProfileUpdate            *time.Time `json:"last_profile_update,omitempty"`
	ReferredBy                   *uuid.UUID `json:"referred_by,omitempty"`
	ReferralCode                 *string    `json:"referral_code,omitempty"`
	AcceptsMarketingEmails       bool       `json:"accepts_marketing_emails"`
	CreatedAt                    time.Time  `json:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at"`
}

// PatientMedicalInfo represents patient medical information
type PatientMedicalInfo struct {
	ID                     uuid.UUID  `json:"id"`
	PatientID              uuid.UUID  `json:"patient_id"`
	BloodType              *string    `json:"blood_type,omitempty"`
	BloodTypeLastTested    *time.Time `json:"blood_type_last_tested,omitempty"`
	HeightCm               *float64   `json:"height_cm,omitempty"`
	WeightKg               *float64   `json:"weight_kg,omitempty"`
	BMI                    *float64   `json:"bmi,omitempty"`
	LastMeasuredDate       *time.Time `json:"last_measured_date,omitempty"`
	OverallHealthStatus    *string    `json:"overall_health_status,omitempty"`
	HealthSummary          *string    `json:"health_summary,omitempty"`
	PrimaryCarePhysician   *string    `json:"primary_care_physician,omitempty"`
	PrimaryClinicID        *uuid.UUID `json:"primary_clinic_id,omitempty"`
	OrganDonor             bool       `json:"organ_donor"`
	AdvanceDirectiveExists bool       `json:"advance_directive_exists"`
	AdvanceDirectiveURL    *string    `json:"advance_directive_url,omitempty"`
	DNRStatus              bool       `json:"dnr_status"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// PatientAllergy represents a patient allergy
type PatientAllergy struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	AllergyName         string     `json:"allergy_name"`
	Severity            string     `json:"severity"` // mild, moderate, severe, life_threatening
	ReactionDescription *string    `json:"reaction_description,omitempty"`
	FirstIdentifiedDate *time.Time `json:"first_identified_date,omitempty"`
	LastOccurrenceDate  *time.Time `json:"last_occurrence_date,omitempty"`
	Status              string     `json:"status"` // active, resolved, inactive
	Notes               *string    `json:"notes,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// PatientMedication represents a patient medication
type PatientMedication struct {
	ID                  uuid.UUID  `json:"id"`
	PatientID           uuid.UUID  `json:"patient_id"`
	MedicationName      string     `json:"medication_name"`
	GenericName         *string    `json:"generic_name,omitempty"`
	Dosage              *string    `json:"dosage,omitempty"`
	Frequency           *string    `json:"frequency,omitempty"`
	Route               *string    `json:"route,omitempty"`
	PrescribingDoctor   *string    `json:"prescribing_doctor,omitempty"`
	PharmacyName        *string    `json:"pharmacy_name,omitempty"`
	PrescriptionDate    *time.Time `json:"prescription_date,omitempty"`
	StartDate           *time.Time `json:"start_date,omitempty"`
	EndDate             *time.Time `json:"end_date,omitempty"`
	ReasonForMedication *string    `json:"reason_for_medication,omitempty"`
	Status              string     `json:"status"` // active, completed, discontinued
	SideEffects         *string    `json:"side_effects,omitempty"`
	Instructions        *string    `json:"instructions,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// PatientCondition represents a patient medical condition
type PatientCondition struct {
	ID              uuid.UUID  `json:"id"`
	PatientID       uuid.UUID  `json:"patient_id"`
	ConditionName   string     `json:"condition_name"`
	ICD10Code       *string    `json:"icd10_code,omitempty"`
	Type            *string    `json:"type,omitempty"` // chronic, acute, genetic, mental_health
	DiagnosedDate   *time.Time `json:"diagnosed_date,omitempty"`
	DiagnosedBy     *string    `json:"diagnosed_by,omitempty"`
	Severity        *string    `json:"severity,omitempty"` // mild, moderate, severe
	Status          string     `json:"status"`             // active, resolved, remission, managed
	Notes           *string    `json:"notes,omitempty"`
	LastFlareUp     *time.Time `json:"last_flare_up,omitempty"`
	NextCheckupDate *time.Time `json:"next_checkup_date,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// PatientImmunization represents a vaccination record
type PatientImmunization struct {
	ID                 uuid.UUID  `json:"id"`
	PatientID          uuid.UUID  `json:"patient_id"`
	VaccineName        string     `json:"vaccine_name"`
	VaccineType        *string    `json:"vaccine_type,omitempty"` // routine, travel, covid, flu
	AdministrationDate time.Time  `json:"administration_date"`
	NextDueDate        *time.Time `json:"next_due_date,omitempty"`
	AdministeredBy     *string    `json:"administered_by,omitempty"`
	ClinicName         *string    `json:"clinic_name,omitempty"`
	LotNumber          *string    `json:"lot_number,omitempty"`
	Manufacturer       *string    `json:"manufacturer,omitempty"`
	DoseNumber         *int       `json:"dose_number,omitempty"`
	TotalDoses         *int       `json:"total_doses,omitempty"`
	Notes              *string    `json:"notes,omitempty"`
	DocumentedBy       *uuid.UUID `json:"documented_by,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// Clinic represents a healthcare facility
type Clinic struct {
	ID                     uuid.UUID      `json:"id"`
	ClinicName             string         `json:"clinic_name"`
	ClinicType             string         `json:"clinic_type"` // public_health_clinic, private_clinic, community_health_center, mobile_clinic
	RegistrationNumber     *string        `json:"registration_number,omitempty"`
	AccreditationNumber    *string        `json:"accreditation_number,omitempty"`
	PrimaryPhone           *string        `json:"primary_phone,omitempty"`
	SecondaryPhone         *string        `json:"secondary_phone,omitempty"`
	EmergencyPhone         *string        `json:"emergency_phone,omitempty"`
	Email                  *string        `json:"email,omitempty"`
	Website                *string        `json:"website,omitempty"`
	PhysicalAddress        string         `json:"physical_address"`
	City                   *string        `json:"city,omitempty"`
	Province               *string        `json:"province,omitempty"`
	PostalCode             *string        `json:"postal_code,omitempty"`
	Country                string         `json:"country"`
	Latitude               *float64       `json:"latitude,omitempty"`
	Longitude              *float64       `json:"longitude,omitempty"`
	GooglePlaceID          *string        `json:"google_place_id,omitempty"`
	Description            *string        `json:"description,omitempty"`
	YearEstablished        *int           `json:"year_established,omitempty"`
	OwnershipType          *string        `json:"ownership_type,omitempty"` // government, private, ngo, religious
	BedCount               *int           `json:"bed_count,omitempty"`
	OperatingHours         map[string]any `json:"operating_hours,omitempty"`
	Services               []string       `json:"services,omitempty"`
	Specialties            []string       `json:"specialties,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	Facilities             []string       `json:"facilities,omitempty"`
	AcceptsMedicalAid      bool           `json:"accepts_medical_aid"`
	MedicalAidProviders    []string       `json:"medical_aid_providers,omitempty"`
	PaymentMethods         []string       `json:"payment_methods,omitempty"`
	FeeStructure           *string        `json:"fee_structure,omitempty"` // free, sliding_scale, fixed_fees
	AccreditationBody      *string        `json:"accreditation_body,omitempty"`
	AccreditationExpiry    *time.Time     `json:"accreditation_expiry,omitempty"`
	IsVerified             bool           `json:"is_verified"`
	VerificationStatus     string         `json:"verification_status"` // pending, verified, rejected
	VerificationNotes      *string        `json:"verification_notes,omitempty"`
	VerifiedBy             *uuid.UUID     `json:"verified_by,omitempty"`
	VerificationDate       *time.Time     `json:"verification_date,omitempty"`
	PatientCapacity        *int           `json:"patient_capacity,omitempty"`
	AverageWaitTimeMinutes *int           `json:"average_wait_time_minutes,omitempty"`
	Rating                 *float64       `json:"rating,omitempty"`
	ReviewCount            int            `json:"review_count"`
	ContactPersonName      *string        `json:"contact_person_name,omitempty"`
	ContactPersonRole      *string        `json:"contact_person_role,omitempty"`
	ContactPersonPhone     *string        `json:"contact_person_phone,omitempty"`
	ContactPersonEmail     *string        `json:"contact_person_email,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

// ClinicFilters represents filters for clinic search
type ClinicFilters struct {
	ClinicType         *string
	Province           *string
	City               *string
	VerificationStatus *string
	AcceptsMedicalAid  *bool
}

// ClinicStaff represents a healthcare worker
type ClinicStaff struct {
	ID                     uuid.UUID      `json:"id"`
	ClinicID               uuid.UUID      `json:"clinic_id"`
	UserID                 uuid.UUID      `json:"user_id"`
	Title                  *string        `json:"title,omitempty"` // Dr, Nurse, Sr, Mr, Ms
	FirstName              string         `json:"first_name"`
	LastName               string         `json:"last_name"`
	ProfessionalTitle      *string        `json:"professional_title,omitempty"` // General Practitioner, Registered Nurse
	Specialization         *string        `json:"specialization,omitempty"`
	WorkEmail              *string        `json:"work_email,omitempty"`
	WorkPhone              *string        `json:"work_phone,omitempty"`
	PersonalPhone          *string        `json:"personal_phone,omitempty"`
	HPCSNumber             *string        `json:"hpcs_number,omitempty"`
	OtherLicenseNumbers    map[string]any `json:"other_license_numbers,omitempty"`
	Qualifications         []string       `json:"qualifications,omitempty"`
	YearsExperience        *int           `json:"years_experience,omitempty"`
	Bio                    *string        `json:"bio,omitempty"`
	StaffRole              string         `json:"staff_role"` // doctor, nurse, administrator, receptionist, manager
	Department             *string        `json:"department,omitempty"`
	IsPrimaryContact       bool           `json:"is_primary_contact"`
	WorkingHours           map[string]any `json:"working_hours,omitempty"`
	AvailableDays          []string       `json:"available_days,omitempty"`
	IsAcceptingNewPatients bool           `json:"is_accepting_new_patients"`
	EmploymentStatus       string         `json:"employment_status"` // active, on_leave, terminated
	StartDate              *time.Time     `json:"start_date,omitempty"`
	EndDate                *time.Time     `json:"end_date,omitempty"`
	ProfilePictureURL      *string        `json:"profile_picture_url,omitempty"`
	LanguagesSpoken        []string       `json:"languages_spoken,omitempty"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
}

// ProfessionalCredential represents a professional credential
type ProfessionalCredential struct {
	ID               uuid.UUID  `json:"id"`
	StaffID          uuid.UUID  `json:"staff_id"`
	CredentialType   string     `json:"credential_type"` // professional_license, specialization, degree, certification
	CredentialNumber *string    `json:"credential_number,omitempty"`
	IssuingAuthority string     `json:"issuing_authority"`
	IssueDate        *time.Time `json:"issue_date,omitempty"`
	ExpiryDate       *time.Time `json:"expiry_date,omitempty"`
	Status           string     `json:"status"` // verified, pending, expired, revoked
	VerifiedBy       *uuid.UUID `json:"verified_by,omitempty"`
	VerificationDate *time.Time `json:"verification_date,omitempty"`
	DocumentURL      *string    `json:"document_url,omitempty"`
	Notes            *string    `json:"notes,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// ClinicService represents a service offered by a clinic
type ClinicService struct {
	ID                      uuid.UUID      `json:"id"`
	ClinicID                uuid.UUID      `json:"clinic_id"`
	ServiceName             string         `json:"service_name"`
	ServiceCategory         *string        `json:"service_category,omitempty"` // preventive, pediatric, adult, testing, women_health
	Description             *string        `json:"description,omitempty"`
	DurationMinutes         *int           `json:"duration_minutes,omitempty"`
	PreparationInstructions *string        `json:"preparation_instructions,omitempty"`
	FollowUpRequired        bool           `json:"follow_up_required"`
	FollowUpDays            *int           `json:"follow_up_days,omitempty"`
	MinimumAge              *int           `json:"minimum_age,omitempty"`
	MaximumAge              *int           `json:"maximum_age,omitempty"`
	GenderRestriction       *string        `json:"gender_restriction,omitempty"` // male, female, none
	Prerequisites           []string       `json:"prerequisites,omitempty"`
	Cost                    *float64       `json:"cost,omitempty"`
	CostCurrency            string         `json:"cost_currency"`
	IsCoveredByMedicalAid   bool           `json:"is_covered_by_medical_aid"`
	MedicalAidCodes         map[string]any `json:"medical_aid_codes,omitempty"`
	IsActive                bool           `json:"is_active"`
	AvailableDays           []string       `json:"available_days,omitempty"`
	RequiresAppointment     bool           `json:"requires_appointment"`
	WalkInAllowed           bool           `json:"walk_in_allowed"`
	ProvidedByStaffIDs      []uuid.UUID    `json:"provided_by_staff_ids,omitempty"`
	PopularityScore         int            `json:"popularity_score"`
	AverageRating           *float64       `json:"average_rating,omitempty"`
	ReviewCount             int            `json:"review_count"`
	CreatedAt               time.Time      `json:"created_at"`
	UpdatedAt               time.Time      `json:"updated_at"`
}

// UserSession represents a user session
type UserSession struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	SessionToken string    `json:"session_token"`
	DeviceType   *string   `json:"device_type,omitempty"` // web, mobile_ios, mobile_android, sms
	DeviceID     *string   `json:"device_id,omitempty"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	UserAgent    *string   `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// PrivacyConsent represents user consent for POPIA compliance
type PrivacyConsent struct {
	ID                         uuid.UUID      `json:"id"`
	UserID                     uuid.UUID      `json:"user_id"`
	HealthDataConsent          bool           `json:"health_data_consent"`
	HealthDataConsentDate      *time.Time     `json:"health_data_consent_date,omitempty"`
	HealthDataConsentVersion   *string        `json:"health_data_consent_version,omitempty"`
	ResearchConsent            bool           `json:"research_consent"`
	ResearchConsentDate        *time.Time     `json:"research_consent_date,omitempty"`
	EmergencyAccessConsent     bool           `json:"emergency_access_consent"`
	EmergencyAccessConsentDate *time.Time     `json:"emergency_access_consent_date,omitempty"`
	SMSCommunicationConsent    bool           `json:"sms_communication_consent"`
	EmailCommunicationConsent  bool           `json:"email_communication_consent"`
	DataSharingConsent         map[string]any `json:"data_sharing_consent,omitempty"`
	SpecialCategoriesConsent   map[string]any `json:"special_categories_consent,omitempty"`
	ConsentWithdrawn           bool           `json:"consent_withdrawn"`
	ConsentWithdrawnDate       *time.Time     `json:"consent_withdrawn_date,omitempty"`
	WithdrawalReason           *string        `json:"withdrawal_reason,omitempty"`
	IPAddress                  *string        `json:"ip_address,omitempty"`
	UserAgent                  *string        `json:"user_agent,omitempty"`
	CreatedAt                  time.Time      `json:"created_at"`
	UpdatedAt                  time.Time      `json:"updated_at"`
}

// UserActivity represents user activity tracking
type UserActivity struct {
	ID              uuid.UUID      `json:"id"`
	UserID          *uuid.UUID     `json:"user_id,omitempty"`
	ActivityType    string         `json:"activity_type"`
	ActivityDetails map[string]any `json:"activity_details,omitempty"`
	IPAddress       *string        `json:"ip_address,omitempty"`
	UserAgent       *string        `json:"user_agent,omitempty"`
	DeviceType      *string        `json:"device_type,omitempty"`
	DeviceID        *string        `json:"device_id,omitempty"`
	Location        map[string]any `json:"location,omitempty"`
	ResourceType    *string        `json:"resource_type,omitempty"`
	ResourceID      *uuid.UUID     `json:"resource_id,omitempty"`
	PerformedAt     time.Time      `json:"performed_at"`
}

// DataAccessLog represents data access audit log for POPIA compliance
type DataAccessLog struct {
	ID                   uuid.UUID      `json:"id"`
	AccessedByUserID     *uuid.UUID     `json:"accessed_by_user_id,omitempty"`
	AccessedByRole       *string        `json:"accessed_by_role,omitempty"`
	AccessedUserID       uuid.UUID      `json:"accessed_user_id"`
	AccessedResourceType *string        `json:"accessed_resource_type,omitempty"`
	AccessedResourceID   *uuid.UUID     `json:"accessed_resource_id,omitempty"`
	AccessType           string         `json:"access_type"` // view, edit, export, delete
	AccessReason         *string        `json:"access_reason,omitempty"`
	IsEmergencyAccess    bool           `json:"is_emergency_access"`
	IPAddress            *string        `json:"ip_address,omitempty"`
	UserAgent            *string        `json:"user_agent,omitempty"`
	Location             map[string]any `json:"location,omitempty"`
	AccessedAt           time.Time      `json:"accessed_at"`
}

// NotificationPreferences represents user notification settings
type NotificationPreferences struct {
	ID                             uuid.UUID `json:"id"`
	UserID                         uuid.UUID `json:"user_id"`
	SMSEnabled                     bool      `json:"sms_enabled"`
	EmailEnabled                   bool      `json:"email_enabled"`
	PushEnabled                    bool      `json:"push_enabled"`
	WhatsappEnabled                bool      `json:"whatsapp_enabled"`
	AppointmentReminders           bool      `json:"appointment_reminders"`
	AppointmentReminderHoursBefore int       `json:"appointment_reminder_hours_before"`
	HealthTips                     bool      `json:"health_tips"`
	HealthTipsFrequency            string    `json:"health_tips_frequency"` // daily, weekly, monthly
	MedicationReminders            bool      `json:"medication_reminders"`
	PrescriptionUpdates            bool      `json:"prescription_updates"`
	ClinicUpdates                  bool      `json:"clinic_updates"`
	Newsletter                     bool      `json:"newsletter"`
	EmergencyAlerts                bool      `json:"emergency_alerts"`
	SystemMaintenance              bool      `json:"system_maintenance"`
	NotificationLanguage           string    `json:"notification_language"`
	QuietHoursStart                *string   `json:"quiet_hours_start,omitempty"` // TIME format
	QuietHoursEnd                  *string   `json:"quiet_hours_end,omitempty"`
	CreatedAt                      time.Time `json:"created_at"`
	UpdatedAt                      time.Time `json:"updated_at"`
}

// SMSConversation represents an SMS conversation state
type SMSConversation struct {
	ID                  uuid.UUID      `json:"id"`
	UserID              *uuid.UUID     `json:"user_id,omitempty"`
	PhoneNumber         string         `json:"phone_number"`
	CurrentMenu         *string        `json:"current_menu,omitempty"` // main, clinic_search, nutrition, callback
	ConversationState   map[string]any `json:"conversation_state,omitempty"`
	LastMessageSent     *string        `json:"last_message_sent,omitempty"`
	LastMessageReceived *string        `json:"last_message_received,omitempty"`
	LastInteractionAt   *time.Time     `json:"last_interaction_at,omitempty"`
	LastLocation        map[string]any `json:"last_location,omitempty"`
	LastSearchQuery     *string        `json:"last_search_query,omitempty"`
	CallbackScheduled   *time.Time     `json:"callback_scheduled,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// SMSMessage represents an SMS message log
type SMSMessage struct {
	ID              uuid.UUID  `json:"id"`
	ConversationID  uuid.UUID  `json:"conversation_id"`
	Direction       string     `json:"direction"` // inbound, outbound
	MessageBody     string     `json:"message_body"`
	TwilioMessageID *string    `json:"twilio_message_id,omitempty"`
	TwilioStatus    *string    `json:"twilio_status,omitempty"`
	SentAt          *time.Time `json:"sent_at,omitempty"`
	DeliveredAt     *time.Time `json:"delivered_at,omitempty"`
	Segments        int        `json:"segments"`
	Cost            *float64   `json:"cost,omitempty"`
	CostCurrency    string     `json:"cost_currency"`
	CreatedAt       time.Time  `json:"created_at"`
}

// OTPVerification represents one-time password verification for password reset
type OTPVerification struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	OTP       string     `json:"otp"`     // 6-digit code
	Type      string     `json:"type"`    // "password_reset", "email_verification"
	Channel   string     `json:"channel"` // "email", "sms"
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
