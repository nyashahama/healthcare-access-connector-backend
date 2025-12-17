-- ============================================
-- User Management Queries
-- ============================================

-- name: CreateUser :one
INSERT INTO users (
    email, phone, password_hash, role, status, 
    is_sms_only, sms_consent_given, popia_consent_given, consent_date
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, email, phone, role, status, is_verified, last_login, 
    login_count, is_sms_only, profile_completion_percentage, created_at, updated_at;


-- name: GetUserByEmail :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    verification_token, verification_expires, last_login, login_count, 
    is_sms_only, sms_consent_given, popia_consent_given, 
    profile_completion_percentage, created_at, updated_at
FROM users
WHERE email = $1 AND status != 'inactive';



-- name: GetUserByPhone :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    last_login, login_count, is_sms_only, sms_consent_given, 
    popia_consent_given, profile_completion_percentage, created_at, updated_at
FROM users
WHERE phone = $1 AND status != 'inactive';


-- name: GetUserByID :one
SELECT id, email, phone, role, status, is_verified, last_login, 
    login_count, is_sms_only, profile_completion_percentage, 
    created_at, updated_at
FROM users
WHERE id = $1 AND status != 'inactive';


-- name: UpdateUserLastLogin :exec
UPDATE users
SET last_login = NOW(), login_count = login_count + 1
WHERE id = $1;


-- name: UpdateUserStatus :exec
UPDATE users
SET status = $2
WHERE id = $1;

-- name: VerifyUser :exec
UPDATE users
SET is_verified = TRUE, verification_token = NULL, verification_expires = NULL
WHERE id = $1;

-- name: SetVerificationToken :exec
UPDATE users
SET verification_token = $2, verification_expires = $3
WHERE id = $1;


-- name: SetPasswordResetToken :exec
UPDATE users
SET reset_password_token = $2, reset_password_expires = $3
WHERE id = $1;


-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2, reset_password_token = NULL, reset_password_expires = NULL
WHERE id = $1;


-- name: ListUsersByRole :many
SELECT id, email, phone, role, status, is_verified, last_login, 
    profile_completion_percentage, created_at
FROM users
WHERE role = $1 AND status != 'inactive'
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;


-- name: CountUsersByRole :one
SELECT COUNT(*) FROM users 
WHERE role = $1 AND status != 'inactive';


-- ============================================
-- Patient Profile Queries
-- ============================================

-- name: CreatePatientProfile :one
INSERT INTO patient_profiles (
    user_id, first_name, last_name, preferred_name, date_of_birth, 
    gender, preferred_gender_pronouns, primary_address, city, province, 
    postal_code, country, language_preferences, home_language, 
    requires_interpreter, preferred_communication_method, 
    medical_aid_number, medical_aid_provider, has_medical_aid, 
    national_id_number, timezone
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
RETURNING id, user_id, first_name, last_name, preferred_name, 
    date_of_birth, gender, city, province, country, 
    preferred_communication_method, created_at, updated_at;


-- name: GetPatientProfileByUserID :one
SELECT id, user_id, first_name, last_name, preferred_name, date_of_birth, 
    gender, preferred_gender_pronouns, primary_address, city, province, 
    postal_code, country, language_preferences, home_language, 
    requires_interpreter, preferred_communication_method, 
    medical_aid_number, medical_aid_provider, has_medical_aid, 
    national_id_number, employment_status, education_level, 
    household_income_range, profile_picture_url, timezone, 
    last_profile_update, referred_by, referral_code, 
    accepts_marketing_emails, created_at, updated_at
FROM patient_profiles
WHERE user_id = $1;   



-- name: GetPatientProfileByID :one
SELECT * FROM patient_profiles WHERE id = $1;


-- name: UpdatePatientProfile :exec
UPDATE patient_profiles
SET first_name = $2, last_name = $3, preferred_name = $4, 
    date_of_birth = $5, gender = $6, primary_address = $7, 
    city = $8, province = $9, postal_code = $10, 
    preferred_communication_method = $11, 
    medical_aid_number = $12, medical_aid_provider = $13, 
    has_medical_aid = $14, employment_status = $15, 
    last_profile_update = NOW()
WHERE id = $1;


-- name: SearchPatients :many
SELECT id, user_id, first_name, last_name, city, province, 
    preferred_communication_method, created_at
FROM patient_profiles
WHERE 
    (first_name ILIKE '%' || $1 || '%' OR last_name ILIKE '%' || $1 || '%')
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY created_at DESC
LIMIT $3 OFFSET $4;



-- ============================================
-- Patient Medical Info Queries
-- ============================================

-- name: CreatePatientMedicalInfo :one
INSERT INTO patient_medical_info (
    patient_id, blood_type, height_cm, weight_kg, bmi, 
    overall_health_status, health_summary, primary_care_physician, 
    primary_clinic_id, organ_donor, dnr_status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, patient_id, blood_type, overall_health_status, created_at, updated_at;


-- name: GetPatientMedicalInfo :one
SELECT * FROM patient_medical_info WHERE patient_id = $1;


-- name: UpdatePatientMedicalInfo :exec
UPDATE patient_medical_info
SET blood_type = $2, height_cm = $3, weight_kg = $4, bmi = $5,
    overall_health_status = $6, health_summary = $7, 
    primary_care_physician = $8, primary_clinic_id = $9,
    last_measured_date = $10
WHERE patient_id = $1;


-- ============================================
-- Patient Allergies Queries
-- ============================================

-- name: AddPatientAllergy :one
INSERT INTO patient_allergies (
    patient_id, allergy_name, severity, reaction_description, 
    first_identified_date, status, notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, patient_id, allergy_name, severity, status, created_at;

-- name: GetPatientAllergies :many
SELECT id, patient_id, allergy_name, severity, reaction_description,
    first_identified_date, last_occurrence_date, status, notes, 
    created_at, updated_at
FROM patient_allergies
WHERE patient_id = $1
ORDER BY severity DESC, created_at DESC;


-- name: UpdatePatientAllergy :exec
UPDATE patient_allergies
SET allergy_name = $2, severity = $3, reaction_description = $4,
    last_occurrence_date = $5, status = $6, notes = $7
WHERE id = $1;


-- name: DeletePatientAllergy :exec
DELETE FROM patient_allergies WHERE id = $1;



-- ============================================
-- Patient Medications Queries
-- ============================================

-- name: AddPatientMedication :one
INSERT INTO patient_medications (
    patient_id, medication_name, generic_name, dosage, frequency, 
    route, prescribing_doctor, pharmacy_name, prescription_date, 
    start_date, end_date, reason_for_medication, status, instructions
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING id, patient_id, medication_name, dosage, frequency, status, created_at;


-- name: GetPatientMedications :many
SELECT id, patient_id, medication_name, generic_name, dosage, 
    frequency, route, prescribing_doctor, start_date, end_date,
    reason_for_medication, status, instructions, created_at, updated_at
FROM patient_medications
WHERE patient_id = $1 
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY start_date DESC;


-- name: UpdatePatientMedication :exec
UPDATE patient_medications
SET medication_name = $2, dosage = $3, frequency = $4, 
    route = $5, end_date = $6, status = $7, 
    side_effects = $8, instructions = $9
WHERE id = $1;


-- ============================================
-- Patient Conditions Queries
-- ============================================

-- name: AddPatientCondition :one
INSERT INTO patient_conditions (
    patient_id, condition_name, icd10_code, type, diagnosed_date, 
    diagnosed_by, severity, status, notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, patient_id, condition_name, type, status, created_at;


-- name: GetPatientConditions :many
SELECT id, patient_id, condition_name, icd10_code, type, 
    diagnosed_date, diagnosed_by, severity, status, notes,
    last_flare_up, next_checkup_date, created_at, updated_at
FROM patient_conditions
WHERE patient_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY diagnosed_date DESC;


-- name: UpdatePatientCondition :exec
UPDATE patient_conditions
SET condition_name = $2, severity = $3, status = $4, 
    notes = $5, last_flare_up = $6, next_checkup_date = $7
WHERE id = $1;


-- ============================================
-- Patient Immunizations Queries
-- ============================================

-- name: AddPatientImmunization :one
INSERT INTO patient_immunizations (
    patient_id, vaccine_name, vaccine_type, administration_date, 
    next_due_date, administered_by, clinic_name, lot_number, 
    manufacturer, dose_number, total_doses, documented_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id, patient_id, vaccine_name, administration_date, next_due_date, created_at;


-- name: GetPatientImmunizations :many
SELECT id, patient_id, vaccine_name, vaccine_type, administration_date,
    next_due_date, administered_by, clinic_name, dose_number, 
    total_doses, notes, created_at
FROM patient_immunizations
WHERE patient_id = $1
ORDER BY administration_date DESC;


-- name: GetUpcomingImmunizations :many
SELECT id, patient_id, vaccine_name, vaccine_type, next_due_date,
    dose_number, total_doses
FROM patient_immunizations
WHERE patient_id = $1 
    AND next_due_date IS NOT NULL 
    AND next_due_date > NOW()
ORDER BY next_due_date ASC;


-- ============================================
-- Clinic Queries
-- ============================================

-- name: CreateClinic :one
INSERT INTO clinics (
    clinic_name, clinic_type, registration_number, primary_phone, 
    email, physical_address, city, province, postal_code, country,
    latitude, longitude, description, ownership_type, 
    accepts_medical_aid, verification_status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
RETURNING id, clinic_name, clinic_type, city, province, 
    verification_status, created_at, updated_at;

-- name: GetClinicByID :one
SELECT * FROM clinics WHERE id = $1;


-- name: UpdateClinic :exec
UPDATE clinics
SET clinic_name = $2, primary_phone = $3, email = $4, 
    description = $5, operating_hours = $6, services = $7,
    specialties = $8, accepts_medical_aid = $9
WHERE id = $1;


-- name: VerifyClinic :exec
UPDATE clinics
SET is_verified = TRUE, verification_status = 'verified',
    verified_by = $2, verification_date = NOW(),
    verification_notes = $3
WHERE id = $1;


-- name: ListClinics :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, email, is_verified,
    verification_status, rating, review_count, created_at
FROM clinics
WHERE 
    ($1::VARCHAR IS NULL OR clinic_type = $1)
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::VARCHAR IS NULL OR verification_status = $4)
ORDER BY rating DESC NULLS LAST, created_at DESC
LIMIT $5 OFFSET $6;


-- name: SearchClinics :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    clinic_name ILIKE '%' || $1 || '%'
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND verification_status = 'verified'
ORDER BY rating DESC NULLS LAST
LIMIT $4 OFFSET $5;


-- name: SearchClinicsByLocation :many
SELECT id, clinic_name, clinic_type, physical_address, city, 
    province, primary_phone, latitude, longitude, rating,
    -- Calculate distance using Haversine formula (approximate)
    (6371 * acos(
        cos(radians($1)) * cos(radians(latitude)) * 
        cos(radians(longitude) - radians($2)) + 
        sin(radians($1)) * sin(radians(latitude))
    )) AS distance_km
FROM clinics
WHERE 
    latitude IS NOT NULL 
    AND longitude IS NOT NULL
    AND verification_status = 'verified'
HAVING distance_km <= $3
ORDER BY distance_km ASC;


-- ============================================
-- Clinic Services Queries
-- ============================================

-- name: AddClinicService :one
INSERT INTO clinic_services (
    clinic_id, service_name, service_category, description,
    duration_minutes, cost, cost_currency, is_covered_by_medical_aid,
    is_active, requires_appointment, walk_in_allowed
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, clinic_id, service_name, service_category, 
    is_active, created_at;


-- name: GetClinicServices :many
SELECT id, clinic_id, service_name, service_category, description,
    duration_minutes, cost, cost_currency, is_covered_by_medical_aid,
    is_active, requires_appointment, walk_in_allowed, 
    average_rating, review_count
FROM clinic_services
WHERE clinic_id = $1 AND is_active = TRUE
ORDER BY popularity_score DESC, service_name ASC;


-- name: UpdateClinicService :exec
UPDATE clinic_services
SET service_name = $2, description = $3, cost = $4,
    is_active = $5, requires_appointment = $6
WHERE id = $1;


-- name: DeactivateClinicService :exec
UPDATE clinic_services SET is_active = FALSE WHERE id = $1;


-- ============================================
-- Clinic Staff Queries
-- ============================================

-- name: CreateClinicStaff :one
INSERT INTO clinic_staff (
    clinic_id, user_id, title, first_name, last_name, 
    professional_title, specialization, work_email, work_phone,
    hpcs_number, staff_role, employment_status, 
    is_accepting_new_patients
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING id, clinic_id, user_id, first_name, last_name, 
    staff_role, employment_status, created_at;


-- name: GetClinicStaffByID :one
SELECT * FROM clinic_staff WHERE id = $1;

-- name: GetClinicStaffByUserID :one
SELECT * FROM clinic_staff WHERE user_id = $1;

-- name: ListClinicStaff :many
SELECT id, clinic_id, user_id, title, first_name, last_name,
    professional_title, specialization, staff_role, 
    employment_status, is_accepting_new_patients, created_at
FROM clinic_staff
WHERE clinic_id = $1 
    AND ($2::VARCHAR IS NULL OR staff_role = $2)
    AND employment_status = 'active'
ORDER BY first_name, last_name;


-- name: UpdateClinicStaff :exec
UPDATE clinic_staff
SET professional_title = $2, specialization = $3, 
    work_email = $4, work_phone = $5, bio = $6,
    is_accepting_new_patients = $7
WHERE id = $1;


-- name: UpdateStaffStatus :exec
UPDATE clinic_staff
SET employment_status = $2, end_date = $3
WHERE id = $1;


-- ============================================
-- Professional Credentials Queries
-- ============================================

-- name: AddProfessionalCredential :one
INSERT INTO professional_credentials (
    staff_id, credential_type, credential_number, issuing_authority,
    issue_date, expiry_date, status, document_url
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, staff_id, credential_type, issuing_authority, 
    status, created_at;

-- name: GetStaffCredentials :many
SELECT id, staff_id, credential_type, credential_number, 
    issuing_authority, issue_date, expiry_date, status,
    verified_by, verification_date, document_url, notes
FROM professional_credentials
WHERE staff_id = $1
ORDER BY issue_date DESC;


-- name: VerifyCredential :exec
UPDATE professional_credentials
SET status = 'verified', verified_by = $2, verification_date = NOW()
WHERE id = $1;


-- name: UpdateCredential :exec
UPDATE professional_credentials
SET credential_number = $2, expiry_date = $3, 
    status = $4, notes = $5
WHERE id = $1;


-- ============================================
-- Session Management Queries
-- ============================================

-- name: CreateSession :one
INSERT INTO user_sessions (
    user_id, session_token, device_type, device_id, 
    ip_address, user_agent, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, session_token, expires_at, created_at;


-- name: GetSession :one
SELECT id, user_id, session_token, device_type, ip_address, 
    user_agent, expires_at, created_at
FROM user_sessions
WHERE session_token = $1 AND expires_at > NOW();


-- name: DeleteSession :exec
DELETE FROM user_sessions WHERE session_token = $1;



-- name: DeleteUserSessions :exec
DELETE FROM user_sessions WHERE user_id = $1;


-- name: DeleteExpiredSessions :exec
DELETE FROM user_sessions WHERE expires_at <= NOW();

-- ============================================
-- Privacy Consent Queries (POPIA Compliance)
-- ============================================

-- name: CreatePrivacyConsent :one
INSERT INTO privacy_consents (
    user_id, health_data_consent, health_data_consent_date,
    health_data_consent_version, emergency_access_consent,
    sms_communication_consent, email_communication_consent,
    ip_address, user_agent
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, user_id, health_data_consent, created_at;


-- name: GetPrivacyConsent :one
SELECT * FROM privacy_consents WHERE user_id = $1;


-- name: UpdatePrivacyConsent :exec
UPDATE privacy_consents
SET health_data_consent = $2, research_consent = $3,
    sms_communication_consent = $4, email_communication_consent = $5,
    data_sharing_consent = $6
WHERE user_id = $1;

-- name: WithdrawConsent :exec
UPDATE privacy_consents
SET consent_withdrawn = TRUE, consent_withdrawn_date = NOW(),
    withdrawal_reason = $2
WHERE user_id = $1;


-- ============================================
-- Audit Logging Queries (POPIA Compliance)
-- ============================================

-- name: LogUserActivity :exec
INSERT INTO user_activities (
    user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, resource_type, resource_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);


-- name: GetUserActivities :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    device_type, resource_type, resource_id, performed_at
FROM user_activities
WHERE user_id = $1
ORDER BY performed_at DESC
LIMIT $2 OFFSET $3;


-- name: LogDataAccess :exec
INSERT INTO data_access_logs (
    accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);


-- name: GetDataAccessLogs :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_resource_type,
    accessed_resource_id, access_type, access_reason, 
    is_emergency_access, accessed_at
FROM data_access_logs
WHERE accessed_user_id = $1
ORDER BY accessed_at DESC
LIMIT $2 OFFSET $3;


-- ============================================
-- Notification Preferences Queries
-- ============================================

-- name: CreateNotificationPreferences :one
INSERT INTO notification_preferences (
    user_id, sms_enabled, email_enabled, push_enabled,
    appointment_reminders, health_tips, notification_language
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, created_at;


-- name: GetNotificationPreferences :one
SELECT * FROM notification_preferences WHERE user_id = $1;


-- name: UpdateNotificationPreferences :exec
UPDATE notification_preferences
SET sms_enabled = $2, email_enabled = $3, push_enabled = $4,
    appointment_reminders = $5, health_tips = $6,
    medication_reminders = $7, emergency_alerts = $8
WHERE user_id = $1;


-- ============================================
-- SMS Conversation Queries
-- ============================================

-- name: CreateSMSConversation :one
INSERT INTO sms_conversations (
    user_id, phone_number, current_menu, conversation_state
)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, phone_number, created_at;

-- name: GetSMSConversationByPhone :one
SELECT * FROM sms_conversations WHERE phone_number = $1;


-- name: UpdateSMSConversation :exec
UPDATE sms_conversations
SET current_menu = $2, conversation_state = $3,
    last_message_sent = $4, last_message_received = $5,
    last_interaction_at = NOW()
WHERE id = $1;
