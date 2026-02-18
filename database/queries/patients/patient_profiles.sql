-- ============================================
-- PATIENT PROFILE REPOSITORY QUERIES
-- Maps to: PatientProfileRepository interface
-- Domain: Patient Profile & Demographics Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreatePatientProfile :one
INSERT INTO patient_profiles (
    user_id, first_name, last_name, preferred_name, date_of_birth,
    gender, preferred_gender_pronouns, primary_address, city, province,
    postal_code, country, language_preferences, home_language,
    requires_interpreter, preferred_communication_method,
    medical_aid_number, medical_aid_provider, has_medical_aid,
    national_id_number, employment_status, education_level,
    household_income_range, timezone, referred_by, referral_code,
    accepts_marketing_emails
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
)
RETURNING *;

-- name: GetPatientProfileByUserID :one
SELECT * FROM patient_profiles
WHERE user_id = $1;

-- name: GetPatientProfileByID :one
SELECT * FROM patient_profiles
WHERE id = $1;

-- name: GetPatientProfileByNationalID :one
SELECT * FROM patient_profiles
WHERE national_id_number = $1
LIMIT 1;

-- name: UpdatePatientProfile :exec
UPDATE patient_profiles
SET 
    first_name = COALESCE($2, first_name),
    last_name = COALESCE($3, last_name),
    preferred_name = COALESCE($4, preferred_name),
    date_of_birth = COALESCE($5, date_of_birth),
    gender = COALESCE($6, gender),
    preferred_gender_pronouns = COALESCE($7, preferred_gender_pronouns),
    primary_address = COALESCE($8, primary_address),
    city = COALESCE($9, city),
    province = COALESCE($10, province),
    postal_code = COALESCE($11, postal_code),
    country = COALESCE($12, country),
    preferred_communication_method = COALESCE($13, preferred_communication_method),
    employment_status = COALESCE($14, employment_status),
    education_level = COALESCE($15, education_level),
    household_income_range = COALESCE($16, household_income_range),
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientProfile :exec
DELETE FROM patient_profiles WHERE id = $1;

-- name: DeletePatientProfileByUserID :exec
DELETE FROM patient_profiles WHERE user_id = $1;

-- ============================================
-- SEARCH & DISCOVERY
-- ============================================

-- name: SearchPatients :many
SELECT 
    id, user_id, first_name, last_name, preferred_name,
    date_of_birth, gender, city, province,
    preferred_communication_method, has_medical_aid,
    created_at, updated_at
FROM patient_profiles
WHERE 
    ($1::TEXT IS NULL OR $1 = '' OR 
     first_name ILIKE '%' || $1 || '%' OR 
     last_name ILIKE '%' || $1 || '%' OR
     preferred_name ILIKE '%' || $1 || '%')
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::BOOLEAN IS NULL OR has_medical_aid = $4)
    AND ($5::VARCHAR IS NULL OR gender = $5)
ORDER BY last_name, first_name
LIMIT $6 OFFSET $7;

-- name: SearchPatientsByName :many
SELECT 
    id, user_id, first_name, last_name, preferred_name,
    city, province, date_of_birth, created_at
FROM patient_profiles
WHERE 
    first_name ILIKE '%' || $1 || '%' 
    OR last_name ILIKE '%' || $1 || '%'
    OR preferred_name ILIKE '%' || $1 || '%'
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;

-- name: ValidatePatientExists :one
SELECT EXISTS(
    SELECT 1 FROM patient_profiles WHERE user_id = $1
) as exists;

-- name: CheckNationalIDExists :one
SELECT EXISTS(
    SELECT 1 FROM patient_profiles 
    WHERE 
        national_id_number = $1
        AND ($2::uuid IS NULL OR user_id != $2)
) as exists;

-- ============================================
-- DEPENDENT OWNERSHIP
-- ============================================

-- name: DependentBelongsToPatient :one
-- Verifies that a dependent record belongs to a given patient.
-- Called by the symptom checker service before accepting a session submission
-- on behalf of a dependent, preventing cross-patient data access.
-- $1 = patient_id (UUID of the patient_profile)
-- $2 = dependent_id (UUID of the patient_dependents row)
SELECT EXISTS(
    SELECT 1
    FROM patient_dependents
    WHERE id         = $2
      AND patient_id = $1
) AS exists;
