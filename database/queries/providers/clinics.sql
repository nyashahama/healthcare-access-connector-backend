-- ============================================
-- CLINIC REPOSITORY QUERIES
-- Maps to: ClinicRepository interface
-- Domain: Healthcare Provider Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateClinic :one
INSERT INTO clinics (
    created_by, owner_user_id,
    clinic_name, clinic_type, registration_number, accreditation_number,
    primary_phone, secondary_phone, emergency_phone, email, website,
    physical_address, city, province, postal_code, country,
    latitude, longitude, google_place_id,
    description, year_established, ownership_type, bed_count, operating_hours,
    services, specialties, languages_spoken, facilities,
    accepts_medical_aid, medical_aid_providers, payment_methods, fee_structure,
    accreditation_body, accreditation_expiry, certifications,
    patient_capacity, average_wait_time_minutes,
    contact_person_name, contact_person_role, contact_person_phone, contact_person_email
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
    $17, $18, $19, $20, $21, $22, $23, $24::jsonb, $25::jsonb, $26::jsonb, $27,
    $28::jsonb, $29, $30::jsonb, $31::jsonb, $32, $33, $34,
    $35::jsonb, $36, $37, $38, $39, $40, $41
)
RETURNING *;


-- name: GetAllClinics :many
SELECT * FROM clinics;

-- name: GetClinicByID :one
SELECT * FROM clinics 
WHERE id = $1;

-- name: UpdateClinic :exec
UPDATE clinics
SET 
    clinic_name = COALESCE($2, clinic_name),
    clinic_type = COALESCE($3, clinic_type),
    primary_phone = COALESCE($4, primary_phone),
    secondary_phone = COALESCE($5, secondary_phone),
    emergency_phone = COALESCE($6, emergency_phone),
    email = COALESCE($7, email),
    website = COALESCE($8, website),
    description = COALESCE($9, description),
    operating_hours = COALESCE($10, operating_hours),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteClinic :exec
DELETE FROM clinics WHERE id = $1;

-- ============================================
-- VERIFICATION & STATUS
-- ============================================

-- name: VerifyClinic :exec
UPDATE clinics
SET 
    is_verified = TRUE,
    verification_status = 'verified',
    verified_by = $2,
    verification_date = NOW(),
    verification_notes = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: RejectClinicVerification :exec
UPDATE clinics
SET 
    is_verified = FALSE,
    verification_status = 'rejected',
    verified_by = $2,
    verification_date = NOW(),
    verification_notes = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicVerificationStatus :exec
UPDATE clinics
SET 
    verification_status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: DeactivateClinic :exec
UPDATE clinics
SET 
    verification_status = 'rejected',
    is_verified = FALSE,
    updated_at = NOW()
WHERE id = $1;

-- name: ReactivateClinic :exec
UPDATE clinics
SET 
    verification_status = 'pending',
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SEARCH & DISCOVERY
-- ============================================

-- name: SearchClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, email,
    rating, review_count, verification_status,
    accepts_medical_aid, created_at
FROM clinics
WHERE 
    (clinic_name ILIKE '%' || $1 || '%'
    OR physical_address ILIKE '%' || $1 || '%'
    OR city ILIKE '%' || $1 || '%')
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::VARCHAR IS NULL OR clinic_type = $4)
    AND verification_status = 'verified'
ORDER BY 
    CASE WHEN clinic_name ILIKE $1 || '%' THEN 1 ELSE 2 END,
    rating DESC NULLS LAST,
    review_count DESC
LIMIT $5 OFFSET $6;

-- ============================================
-- FILTERING & LISTING
-- ============================================

-- name: ListClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, email,
    is_verified, verification_status,
    rating, review_count, created_at
FROM clinics
WHERE 
    ($1::VARCHAR IS NULL OR clinic_type = $1)
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::VARCHAR IS NULL OR verification_status = $4)
ORDER BY rating DESC NULLS LAST, created_at DESC
LIMIT $5 OFFSET $6;

-- name: GetVerifiedClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, email,
    rating, review_count, created_at
FROM clinics
WHERE verification_status = 'verified'
ORDER BY rating DESC NULLS LAST
LIMIT $1 OFFSET $2;

-- name: GetPendingVerificationClinics :many
SELECT 
    id, clinic_name, clinic_type, registration_number,
    city, province, email, primary_phone,
    created_at, verification_status
FROM clinics
WHERE verification_status = 'pending'
ORDER BY created_at ASC
LIMIT $1 OFFSET $2;

-- ============================================
-- PROVIDER REGISTRATION QUERIES 
-- ============================================

-- name: GetClinicByOwner :one
SELECT * FROM clinics
WHERE owner_user_id = $1
ORDER BY created_at DESC
LIMIT 1;

-- name: GetClinicsByCreator :many
SELECT * FROM clinics
WHERE created_by = $1
ORDER BY created_at DESC;

-- name: GetClinicWithOwnerInfo :one
SELECT 
    c.*,
    u.email as owner_email,
    u.phone as owner_phone,
    cs.first_name as owner_first_name,
    cs.last_name as owner_last_name
FROM clinics c
LEFT JOIN users u ON c.owner_user_id = u.id
LEFT JOIN clinic_staff cs ON c.owner_user_id = cs.user_id AND cs.clinic_id = c.id
WHERE c.id = $1;

-- name: UpdateClinicOwner :exec
UPDATE clinics
SET 
    owner_user_id = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetClinicVerificationStatus :one
SELECT 
    id,
    clinic_name,
    verification_status,
    is_verified,
    verification_notes,
    verification_date,
    created_at
FROM clinics
WHERE id = $1;
