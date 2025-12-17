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
