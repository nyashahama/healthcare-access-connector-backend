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
