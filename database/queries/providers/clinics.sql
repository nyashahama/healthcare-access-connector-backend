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
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
    $15, $16, $17, $18, $19, $20, $21, $22::jsonb, $23::jsonb, $24::jsonb, $25,
    $26::jsonb, $27, $28::jsonb, $29::jsonb, $30, $31, $32,
    $33::jsonb, $34, $35, $36, $37, $38, $39
)
RETURNING *;
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
-- LOCATION MANAGEMENT
-- ============================================

-- name: UpdateClinicLocation :exec
UPDATE clinics
SET 
    physical_address = $2,
    city = $3,
    province = $4,
    postal_code = $5,
    country = COALESCE($6, country),
    latitude = $7,
    longitude = $8,
    google_place_id = $9,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicCoordinates :exec
UPDATE clinics
SET 
    latitude = $2,
    longitude = $3,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- CONTACT INFORMATION
-- ============================================

-- name: UpdateClinicContact :exec
UPDATE clinics
SET 
    primary_phone = COALESCE($2, primary_phone),
    secondary_phone = $3,
    emergency_phone = $4,
    email = COALESCE($5, email),
    website = $6,
    contact_person_name = $7,
    contact_person_role = $8,
    contact_person_phone = $9,
    contact_person_email = $10,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SERVICES & CAPABILITIES
-- ============================================

-- name: UpdateClinicServices :exec
UPDATE clinics
SET 
    services = $2,
    specialties = $3,
    facilities = $4,
    languages_spoken = $5,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicOperatingHours :exec
UPDATE clinics
SET 
    operating_hours = $2,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- PAYMENT & INSURANCE
-- ============================================

-- name: UpdateClinicPaymentInfo :exec
UPDATE clinics
SET 
    accepts_medical_aid = $2,
    medical_aid_providers = $3,
    payment_methods = $4,
    fee_structure = $5,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- ACCREDITATION & CERTIFICATION
-- ============================================

-- name: UpdateClinicAccreditation :exec
UPDATE clinics
SET 
    accreditation_number = $2,
    accreditation_body = $3,
    accreditation_expiry = $4,
    certifications = $5,
    updated_at = NOW()
WHERE id = $1;

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
-- RATINGS & REVIEWS
-- ============================================

-- name: UpdateClinicRating :exec
UPDATE clinics
SET 
    rating = $2,
    review_count = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: IncrementReviewCount :exec
UPDATE clinics
SET 
    review_count = review_count + 1,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- OPERATIONAL METRICS
-- ============================================

-- name: UpdateClinicCapacity :exec
UPDATE clinics
SET 
    patient_capacity = $2,
    bed_count = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateAverageWaitTime :exec
UPDATE clinics
SET 
    average_wait_time_minutes = $2,
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

-- name: SearchClinicsByName :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    clinic_name ILIKE '%' || $1 || '%'
    AND verification_status = 'verified'
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY 
    rating DESC NULLS LAST,
    clinic_name ASC
LIMIT $3 OFFSET $4;

-- name: SearchClinicsByLocation :many
SELECT 
    id, clinic_name, clinic_type,
    physical_address, city, province,
    primary_phone, latitude, longitude, rating,
    CAST((6371 * acos(
        cos(radians($1)) * cos(radians(latitude)) * 
        cos(radians(longitude) - radians($2)) + 
        sin(radians($1)) * sin(radians(latitude))
    )) AS NUMERIC(10,2)) AS distance_km
FROM clinics
WHERE 
    latitude IS NOT NULL 
    AND longitude IS NOT NULL
    AND verification_status = 'verified'
    AND (6371 * acos(
        cos(radians($1)) * cos(radians(latitude)) * 
        cos(radians(longitude) - radians($2)) + 
        sin(radians($1)) * sin(radians(latitude))
    )) <= $3
ORDER BY distance_km ASC
LIMIT $4;

-- name: GetNearbyClinicsByService :many
SELECT 
    id, clinic_name, clinic_type,
    physical_address, city, province,
    primary_phone, latitude, longitude,
    rating, services,
    CAST((6371 * acos(
        cos(radians($1)) * cos(radians(latitude)) * 
        cos(radians(longitude) - radians($2)) + 
        sin(radians($1)) * sin(radians(latitude))
    )) AS NUMERIC(10,2)) AS distance_km
FROM clinics
WHERE 
    latitude IS NOT NULL 
    AND longitude IS NOT NULL
    AND verification_status = 'verified'
    AND services @> $3::jsonb
    AND (6371 * acos(
        cos(radians($1)) * cos(radians(latitude)) * 
        cos(radians(longitude) - radians($2)) + 
        sin(radians($1)) * sin(radians(latitude))
    )) <= $4
ORDER BY distance_km ASC
LIMIT $5;

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

-- name: GetClinicsByType :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    clinic_type = $1
    AND verification_status = 'verified'
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsByProvince :many
SELECT 
    id, clinic_name, clinic_type, city,
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    province = $1
    AND verification_status = 'verified'
ORDER BY rating DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: GetClinicsByOwnership :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, ownership_type, rating, review_count
FROM clinics
WHERE 
    ownership_type = $1
    AND verification_status = 'verified'
ORDER BY rating DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- ============================================
-- SERVICE-BASED QUERIES
-- ============================================

-- name: GetClinicsByService :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count, services
FROM clinics
WHERE 
    verification_status = 'verified'
    AND services @> $1::jsonb
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsBySpecialty :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count, specialties
FROM clinics
WHERE 
    verification_status = 'verified'
    AND specialties @> $1::jsonb
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsWithFacility :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, facilities
FROM clinics
WHERE 
    verification_status = 'verified'
    AND facilities @> $1::jsonb
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- ============================================
-- MEDICAL AID & PAYMENT
-- ============================================

-- name: GetClinicsAcceptingMedicalAid :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count,
    medical_aid_providers, payment_methods
FROM clinics
WHERE 
    verification_status = 'verified'
    AND accepts_medical_aid = TRUE
    AND ($1::VARCHAR IS NULL OR province = $1)
    AND ($2::jsonb IS NULL OR medical_aid_providers @> $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsByPaymentMethod :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    primary_phone, payment_methods, fee_structure
FROM clinics
WHERE 
    verification_status = 'verified'
    AND payment_methods @> $1::jsonb
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsByFeeStructure :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    primary_phone, fee_structure
FROM clinics
WHERE 
    verification_status = 'verified'
    AND fee_structure = $1
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- ============================================
-- RANKING & DISCOVERY
-- ============================================

-- name: GetTopRatedClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    verification_status = 'verified'
    AND rating IS NOT NULL
    AND review_count >= $2
    AND ($1::VARCHAR IS NULL OR province = $1)
ORDER BY rating DESC, review_count DESC
LIMIT $3;

-- name: GetMostReviewedClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    verification_status = 'verified'
    AND review_count > 0
    AND ($1::VARCHAR IS NULL OR province = $1)
ORDER BY review_count DESC, rating DESC NULLS LAST
LIMIT $2;

-- name: GetRecentlyAddedClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, rating, review_count, created_at
FROM clinics
WHERE 
    verification_status = 'verified'
    AND ($1::VARCHAR IS NULL OR province = $1)
ORDER BY created_at DESC
LIMIT $2;

-- name: GetRecentlyVerifiedClinics :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, verification_date
FROM clinics
WHERE 
    verification_status = 'verified'
    AND verification_date IS NOT NULL
ORDER BY verification_date DESC
LIMIT $1;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: GetClinicStatistics :one
SELECT 
    c.id,
    c.clinic_name,
    c.review_count,
    c.rating,
    c.patient_capacity,
    c.bed_count,
    c.average_wait_time_minutes,
    COUNT(DISTINCT cs.id) FILTER (WHERE cs.employment_status = 'active') as active_staff_count,
    COUNT(DISTINCT cs.id) as total_staff_count,
    COUNT(DISTINCT srv.id) FILTER (WHERE srv.is_active = TRUE) as active_services_count,
    COUNT(DISTINCT srv.id) as total_services_count
FROM clinics c
LEFT JOIN clinic_staff cs ON c.id = cs.clinic_id
LEFT JOIN clinic_services srv ON c.id = srv.clinic_id
WHERE c.id = $1
GROUP BY c.id;

-- name: GetClinicMetrics :one
SELECT 
    COUNT(*) as total_clinics,
    COUNT(*) FILTER (WHERE verification_status = 'verified') as verified_clinics,
    COUNT(*) FILTER (WHERE verification_status = 'pending') as pending_clinics,
    COUNT(*) FILTER (WHERE verification_status = 'rejected') as rejected_clinics,
    COUNT(*) FILTER (WHERE is_verified = TRUE) as active_clinics,
    AVG(rating) FILTER (WHERE rating IS NOT NULL) as average_rating,
    SUM(review_count) as total_reviews,
    AVG(patient_capacity) FILTER (WHERE patient_capacity IS NOT NULL) as avg_capacity,
    SUM(bed_count) FILTER (WHERE bed_count IS NOT NULL) as total_beds
FROM clinics;

-- name: GetClinicTypeDistribution :many
SELECT 
    clinic_type,
    COUNT(*) as count,
    AVG(rating) FILTER (WHERE rating IS NOT NULL) as avg_rating
FROM clinics
WHERE verification_status = 'verified'
GROUP BY clinic_type
ORDER BY count DESC;

-- name: GetClinicProvinceDistribution :many
SELECT 
    province,
    COUNT(*) as count,
    AVG(rating) FILTER (WHERE rating IS NOT NULL) as avg_rating
FROM clinics
WHERE 
    verification_status = 'verified'
    AND province IS NOT NULL
GROUP BY province
ORDER BY count DESC;

-- name: GetClinicOwnershipDistribution :many
SELECT 
    ownership_type,
    COUNT(*) as count,
    AVG(rating) FILTER (WHERE rating IS NOT NULL) as avg_rating
FROM clinics
WHERE 
    verification_status = 'verified'
    AND ownership_type IS NOT NULL
GROUP BY ownership_type
ORDER BY count DESC;

-- ============================================
-- COUNTING & EXISTENCE CHECKS
-- ============================================

-- name: CountClinics :one
SELECT COUNT(*) FROM clinics
WHERE 
    ($1::VARCHAR IS NULL OR clinic_type = $1)
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR verification_status = $3);

-- name: CountVerifiedClinics :one
SELECT COUNT(*) FROM clinics
WHERE verification_status = 'verified';

-- name: CountClinicsByProvince :one
SELECT COUNT(*) FROM clinics
WHERE 
    province = $1
    AND verification_status = 'verified';

-- name: ClinicExists :one
SELECT EXISTS(
    SELECT 1 FROM clinics WHERE id = $1
) as exists;

-- name: CheckRegistrationNumberExists :one
SELECT EXISTS(
    SELECT 1 FROM clinics 
    WHERE registration_number = $1
    AND ($2::uuid IS NULL OR id != $2)
) as exists;

-- name: CheckEmailExists :one
SELECT EXISTS(
    SELECT 1 FROM clinics 
    WHERE email = $1
    AND ($2::uuid IS NULL OR id != $2)
) as exists;

-- name: CheckPhoneExists :one
SELECT EXISTS(
    SELECT 1 FROM clinics 
    WHERE primary_phone = $1
    AND ($2::uuid IS NULL OR id != $2)
) as exists;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetClinicsByIDs :many
SELECT * FROM clinics
WHERE id = ANY($1::uuid[])
ORDER BY clinic_name;

-- name: BulkUpdateVerificationStatus :exec
UPDATE clinics
SET 
    verification_status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkVerifyClinics :exec
UPDATE clinics
SET 
    is_verified = TRUE,
    verification_status = 'verified',
    verified_by = $2,
    verification_date = NOW(),
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- ============================================
-- REFERENCE DATA LOOKUPS
-- ============================================

-- name: GetClinicByRegistrationNumber :one
SELECT * FROM clinics 
WHERE registration_number = $1
LIMIT 1;

-- name: GetClinicByEmail :one
SELECT * FROM clinics
WHERE email = $1
LIMIT 1;

-- name: GetClinicByPhone :one
SELECT * FROM clinics
WHERE primary_phone = $1
LIMIT 1;

-- ============================================
-- ADVANCED SEARCH
-- ============================================

-- name: SearchClinicsAdvanced :many
SELECT 
    id, clinic_name, clinic_type, city, province,
    physical_address, primary_phone, email,
    rating, review_count, accepts_medical_aid,
    services, specialties, facilities
FROM clinics
WHERE 
    verification_status = 'verified'
    AND (
        $1::TEXT IS NULL OR
        clinic_name ILIKE '%' || $1 || '%'
        OR physical_address ILIKE '%' || $1 || '%'
        OR city ILIKE '%' || $1 || '%'
    )
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::VARCHAR IS NULL OR clinic_type = $4)
    AND ($5::VARCHAR IS NULL OR ownership_type = $5)
    AND ($6::BOOLEAN IS NULL OR accepts_medical_aid = $6)
    AND ($7::jsonb IS NULL OR services @> $7)
    AND ($8::jsonb IS NULL OR specialties @> $8)
ORDER BY 
    CASE 
        WHEN clinic_name ILIKE $1 || '%' THEN 1
        WHEN clinic_name ILIKE '%' || $1 || '%' THEN 2
        ELSE 3
    END,
    rating DESC NULLS LAST,
    review_count DESC
LIMIT $9 OFFSET $10;

-- name: GetClinicsWithExpiredAccreditation :many
SELECT 
    id, clinic_name, accreditation_number,
    accreditation_body, accreditation_expiry,
    email, primary_phone
FROM clinics
WHERE 
    accreditation_expiry < CURRENT_DATE
    AND verification_status = 'verified'
ORDER BY accreditation_expiry ASC;

-- name: GetClinicsNeedingReaccreditation :many
SELECT 
    id, clinic_name, accreditation_number,
    accreditation_body, accreditation_expiry,
    email, primary_phone
FROM clinics
WHERE 
    accreditation_expiry <= CURRENT_DATE + INTERVAL '30 days'
    AND accreditation_expiry >= CURRENT_DATE
    AND verification_status = 'verified'
ORDER BY accreditation_expiry ASC;
