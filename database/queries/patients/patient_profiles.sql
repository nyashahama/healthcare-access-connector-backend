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
    national_id_number, employment_status, education_level,
    household_income_range, timezone, referred_by, referral_code,
    accepts_marketing_emails
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
RETURNING id, user_id, first_name, last_name, preferred_name, 
    date_of_birth, gender, city, province, country, 
    preferred_communication_method, has_medical_aid, timezone,
    created_at, updated_at;


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
WHERE id = $1;


-- name: GetPatientProfileByNationalID :one
SELECT id, user_id, first_name, last_name, preferred_name, date_of_birth, 
    gender, city, province, has_medical_aid, created_at, updated_at
FROM patient_profiles
WHERE national_id_number = $1;


-- name: UpdatePatientProfile :exec
UPDATE patient_profiles
SET first_name = COALESCE($2, first_name),
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


-- name: UpdatePatientPersonalInfo :exec
UPDATE patient_profiles
SET first_name = $2,
    last_name = $3,
    preferred_name = $4,
    date_of_birth = $5,
    gender = $6,
    preferred_gender_pronouns = $7,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientContactInfo :exec
UPDATE patient_profiles
SET primary_address = $2,
    city = $3,
    province = $4,
    postal_code = $5,
    country = $6,
    preferred_communication_method = $7,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientLanguagePreferences :exec
UPDATE patient_profiles
SET language_preferences = $2,
    home_language = $3,
    requires_interpreter = $4,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientMedicalAidInfo :exec
UPDATE patient_profiles
SET medical_aid_number = $2,
    medical_aid_provider = $3,
    has_medical_aid = $4,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientDemographicInfo :exec
UPDATE patient_profiles
SET employment_status = $2,
    education_level = $3,
    household_income_range = $4,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientProfilePicture :exec
UPDATE patient_profiles
SET profile_picture_url = $2,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientTimezone :exec
UPDATE patient_profiles
SET timezone = $2,
    last_profile_update = NOW(),
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientMarketingPreferences :exec
UPDATE patient_profiles
SET accepts_marketing_emails = $2,
    updated_at = NOW()
WHERE user_id = $1;


-- name: UpdatePatientReferralInfo :exec
UPDATE patient_profiles
SET referred_by = $2,
    referral_code = $3,
    updated_at = NOW()
WHERE user_id = $1;


-- name: SearchPatients :many
SELECT id, user_id, first_name, last_name, preferred_name, 
    date_of_birth, gender, city, province, 
    preferred_communication_method, has_medical_aid,
    created_at, updated_at
FROM patient_profiles
WHERE 
    ($1 = '' OR 
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
SELECT id, user_id, first_name, last_name, preferred_name,
    city, province, date_of_birth, created_at
FROM patient_profiles
WHERE first_name ILIKE '%' || $1 || '%' 
   OR last_name ILIKE '%' || $1 || '%'
   OR preferred_name ILIKE '%' || $1 || '%'
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsByProvince :many
SELECT id, user_id, first_name, last_name, city, province,
    preferred_communication_method, created_at
FROM patient_profiles
WHERE province = $1
ORDER BY city, last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsByCity :many
SELECT id, user_id, first_name, last_name, city, province,
    preferred_communication_method, created_at
FROM patient_profiles
WHERE city = $1
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsWithMedicalAid :many
SELECT id, user_id, first_name, last_name, 
    medical_aid_provider, medical_aid_number,
    city, province, created_at
FROM patient_profiles
WHERE has_medical_aid = true
    AND ($1::VARCHAR IS NULL OR medical_aid_provider = $1)
ORDER BY medical_aid_provider, last_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsWithoutMedicalAid :many
SELECT id, user_id, first_name, last_name, 
    city, province, household_income_range, created_at
FROM patient_profiles
WHERE has_medical_aid = false
ORDER BY province, city, last_name
LIMIT $1 OFFSET $2;


-- name: GetPatientsByLanguage :many
SELECT id, user_id, first_name, last_name, 
    home_language, language_preferences, city, province
FROM patient_profiles
WHERE home_language = $1 OR $1 = ANY(language_preferences)
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsRequiringInterpreter :many
SELECT id, user_id, first_name, last_name, 
    home_language, language_preferences, 
    preferred_communication_method, city, province
FROM patient_profiles
WHERE requires_interpreter = true
ORDER BY province, city, last_name
LIMIT $1 OFFSET $2;


-- name: GetPatientsByCommunicationMethod :many
SELECT id, user_id, first_name, last_name, 
    preferred_communication_method, city, province, created_at
FROM patient_profiles
WHERE preferred_communication_method = $1
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsByReferrer :many
SELECT id, user_id, first_name, last_name, 
    referral_code, city, province, created_at
FROM patient_profiles
WHERE referred_by = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;


-- name: GetPatientsByReferralCode :many
SELECT id, user_id, first_name, last_name, 
    referred_by, city, province, created_at
FROM patient_profiles
WHERE referral_code = $1
ORDER BY created_at DESC;


-- name: GetPatientsAcceptingMarketing :many
SELECT id, user_id, first_name, last_name, 
    preferred_communication_method, language_preferences,
    city, province, created_at
FROM patient_profiles
WHERE accepts_marketing_emails = true
    AND ($1::VARCHAR IS NULL OR province = $1)
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsByAgeRange :many
SELECT id, user_id, first_name, last_name, 
    date_of_birth, gender, city, province, created_at
FROM patient_profiles
WHERE date_of_birth IS NOT NULL
    AND date_of_birth BETWEEN $1 AND $2
ORDER BY date_of_birth DESC
LIMIT $3 OFFSET $4;


-- name: GetPatientsByGender :many
SELECT id, user_id, first_name, last_name, 
    gender, date_of_birth, city, province, created_at
FROM patient_profiles
WHERE gender = $1
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientProfilesByUserIDs :many
SELECT id, user_id, first_name, last_name, preferred_name,
    date_of_birth, gender, city, province, 
    preferred_communication_method, has_medical_aid, created_at
FROM patient_profiles
WHERE user_id = ANY($1::uuid[])
ORDER BY last_name, first_name;


-- name: GetIncompleteProfiles :many
SELECT id, user_id, first_name, last_name, 
    date_of_birth, primary_address, medical_aid_number,
    last_profile_update, created_at
FROM patient_profiles
WHERE date_of_birth IS NULL 
   OR primary_address IS NULL 
   OR city IS NULL 
   OR province IS NULL
   OR ($1 AND medical_aid_number IS NULL)
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;


-- name: GetRecentlyUpdatedProfiles :many
SELECT id, user_id, first_name, last_name, 
    last_profile_update, updated_at
FROM patient_profiles
WHERE last_profile_update >= $1
ORDER BY last_profile_update DESC
LIMIT $2 OFFSET $3;


-- name: GetStaleProfiles :many
SELECT id, user_id, first_name, last_name, 
    last_profile_update, created_at
FROM patient_profiles
WHERE last_profile_update < $1 
   OR last_profile_update IS NULL
ORDER BY last_profile_update ASC NULLS FIRST
LIMIT $2 OFFSET $3;


-- name: CountPatientsByProvince :one
SELECT province, COUNT(*) as patient_count
FROM patient_profiles
WHERE province IS NOT NULL
GROUP BY province
ORDER BY patient_count DESC;


-- name: CountPatientsByMedicalAidStatus :one
SELECT 
    COUNT(*) FILTER (WHERE has_medical_aid = true) as with_medical_aid,
    COUNT(*) FILTER (WHERE has_medical_aid = false) as without_medical_aid,
    COUNT(*) as total_patients
FROM patient_profiles;


-- name: CountPatientsByCommunicationMethod :one
SELECT 
    COUNT(*) FILTER (WHERE preferred_communication_method = 'sms') as sms_count,
    COUNT(*) FILTER (WHERE preferred_communication_method = 'email') as email_count,
    COUNT(*) FILTER (WHERE preferred_communication_method = 'whatsapp') as whatsapp_count,
    COUNT(*) FILTER (WHERE preferred_communication_method = 'call') as call_count
FROM patient_profiles;


-- name: GetPatientDemographicsSummary :one
SELECT 
    COUNT(*) as total_patients,
    COUNT(DISTINCT province) as provinces_covered,
    COUNT(DISTINCT city) as cities_covered,
    COUNT(*) FILTER (WHERE has_medical_aid = true) as with_medical_aid,
    COUNT(*) FILTER (WHERE requires_interpreter = true) as requiring_interpreter,
    COUNT(*) FILTER (WHERE accepts_marketing_emails = true) as marketing_opt_in,
    AVG(EXTRACT(YEAR FROM AGE(date_of_birth))) as average_age
FROM patient_profiles
WHERE date_of_birth IS NOT NULL;


-- name: DeletePatientProfile :exec
DELETE FROM patient_profiles WHERE id = $1;


-- name: DeletePatientProfileByUserID :exec
DELETE FROM patient_profiles WHERE user_id = $1;


-- name: BulkUpdatePatientProvince :exec
UPDATE patient_profiles
SET province = $2, updated_at = NOW()
WHERE id = ANY($1::uuid[]);


-- name: BulkUpdateCommunicationMethod :exec
UPDATE patient_profiles
SET preferred_communication_method = $2, updated_at = NOW()
WHERE id = ANY($1::uuid[]);


-- name: ValidatePatientExists :one
SELECT EXISTS(
    SELECT 1 FROM patient_profiles WHERE user_id = $1
) as exists;


-- name: GetPatientFullName :one
SELECT 
    CASE 
        WHEN preferred_name IS NOT NULL AND preferred_name != '' 
        THEN preferred_name || ' ' || last_name
        ELSE first_name || ' ' || last_name
    END as full_name
FROM patient_profiles
WHERE user_id = $1;


-- name: GetPatientsByIncomeRange :many
SELECT id, user_id, first_name, last_name, 
    household_income_range, employment_status,
    city, province, created_at
FROM patient_profiles
WHERE household_income_range = $1
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: GetPatientsByEmploymentStatus :many
SELECT id, user_id, first_name, last_name, 
    employment_status, education_level,
    city, province, created_at
FROM patient_profiles
WHERE employment_status = $1
ORDER BY last_name, first_name
LIMIT $2 OFFSET $3;


-- name: ExportPatientData :many
SELECT id, user_id, first_name, last_name, preferred_name, 
    date_of_birth, gender, primary_address, city, province, 
    postal_code, country, preferred_communication_method,
    medical_aid_provider, has_medical_aid, employment_status,
    created_at, updated_at
FROM patient_profiles
WHERE user_id = $1;


-- name: AdvancedPatientSearch :many
SELECT id, user_id, first_name, last_name, preferred_name,
    date_of_birth, gender, city, province, 
    preferred_communication_method, has_medical_aid,
    medical_aid_provider, employment_status, created_at
FROM patient_profiles
WHERE ($1::VARCHAR IS NULL OR 
       first_name ILIKE '%' || $1 || '%' OR 
       last_name ILIKE '%' || $1 || '%' OR
       preferred_name ILIKE '%' || $1 || '%')
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::BOOLEAN IS NULL OR has_medical_aid = $4)
    AND ($5::VARCHAR IS NULL OR gender = $5)
    AND ($6::VARCHAR IS NULL OR preferred_communication_method = $6)
    AND ($7::VARCHAR IS NULL OR employment_status = $7)
    AND ($8::VARCHAR IS NULL OR medical_aid_provider = $8)
    AND ($9::BOOLEAN IS NULL OR requires_interpreter = $9)
    AND ($10::BOOLEAN IS NULL OR accepts_marketing_emails = $10)
ORDER BY last_name, first_name
LIMIT $11 OFFSET $12;
