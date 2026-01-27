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
SELECT 
    id, 
    clinic_name, 
    clinic_type, 
    physical_address, 
    city, 
    province, 
    primary_phone, 
    latitude, 
    longitude, 
    rating,
    -- Calculate distance using Haversine formula (approximate)
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
ORDER BY distance_km ASC;

-- name: CountClinics :one
SELECT COUNT(*) FROM clinics
WHERE ($1::VARCHAR IS NULL OR clinic_type = $1)
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR verification_status = $3);

-- name: UpdateClinicStatus :exec
UPDATE clinics
SET verification_status = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicRating :exec
UPDATE clinics
SET rating = $2, review_count = $3, updated_at = NOW()
WHERE id = $1;

-- name: GetClinicsByIDs :many
SELECT * FROM clinics
WHERE id = ANY($1::uuid[])
ORDER BY clinic_name;

-- name: DeleteClinic :exec
DELETE FROM clinics WHERE id = $1;

-- name: GetClinicByRegistrationNumber :one
SELECT * FROM clinics 
WHERE registration_number = $1
LIMIT 1;

-- name: GetVerifiedClinics :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, email, rating, review_count, created_at
FROM clinics
WHERE verification_status = 'verified'
ORDER BY rating DESC NULLS LAST
LIMIT $1 OFFSET $2;

-- name: GetClinicsByService :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE verification_status = 'verified'
    AND services @> $1::jsonb
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsBySpecialty :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE verification_status = 'verified'
    AND specialties @> $1::jsonb
    AND ($2::VARCHAR IS NULL OR province = $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsAcceptingMedicalAid :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count,
    medical_aid_providers
FROM clinics
WHERE verification_status = 'verified'
    AND accepts_medical_aid = TRUE
    AND ($1::VARCHAR IS NULL OR province = $1)
    AND ($2::jsonb IS NULL OR medical_aid_providers @> $2)
ORDER BY rating DESC NULLS LAST
LIMIT $3 OFFSET $4;

-- name: GetClinicsByOwnership :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, ownership_type, rating, review_count
FROM clinics
WHERE ownership_type = $1
    AND verification_status = 'verified'
ORDER BY rating DESC NULLS LAST
LIMIT $2 OFFSET $3;

-- name: GetTopRatedClinics :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE verification_status = 'verified'
    AND rating IS NOT NULL
    AND ($1::VARCHAR IS NULL OR province = $1)
ORDER BY rating DESC, review_count DESC
LIMIT $2;

-- name: GetRecentlyAddedClinics :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count, created_at
FROM clinics
WHERE verification_status = 'verified'
    AND ($1::VARCHAR IS NULL OR province = $1)
ORDER BY created_at DESC
LIMIT $2;

-- name: UpdateClinicLocation :exec
UPDATE clinics
SET latitude = $2, longitude = $3, 
    physical_address = $4, city = $5, province = $6,
    postal_code = $7, updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicContact :exec
UPDATE clinics
SET primary_phone = $2, secondary_phone = $3, emergency_phone = $4,
    email = $5, website = $6, updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicServices :exec
UPDATE clinics
SET services = $2, specialties = $3, facilities = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateClinicMedicalAid :exec
UPDATE clinics
SET accepts_medical_aid = $2, medical_aid_providers = $3,
    payment_methods = $4, fee_structure = $5, updated_at = NOW()
WHERE id = $1;

-- name: GetClinicStatistics :one
SELECT 
    c.id,
    c.review_count,
    c.rating,
    COUNT(DISTINCT cs.id) FILTER (WHERE cs.status = 'active') as active_staff_count,
    COUNT(DISTINCT cs.id) as total_staff_count
FROM clinics c
LEFT JOIN clinic_staff cs ON c.id = cs.clinic_id
WHERE c.id = $1
GROUP BY c.id, c.review_count, c.rating;

-- name: GetClinicMetrics :one
SELECT 
    COUNT(*) as total_clinics,
    COUNT(*) FILTER (WHERE verification_status = 'verified') as verified_clinics,
    COUNT(*) FILTER (WHERE verification_status = 'pending') as pending_clinics,
    COUNT(*) FILTER (WHERE verification_status = 'rejected') as rejected_clinics,
    AVG(rating) FILTER (WHERE rating IS NOT NULL) as average_rating,
    SUM(review_count) as total_reviews
FROM clinics;

-- name: GetClinicsByType :many
SELECT clinic_type, COUNT(*) as count
FROM clinics
WHERE verification_status = 'verified'
GROUP BY clinic_type
ORDER BY count DESC;

-- name: GetClinicsByProvince :many
SELECT province, COUNT(*) as count
FROM clinics
WHERE verification_status = 'verified'
    AND province IS NOT NULL
GROUP BY province
ORDER BY count DESC;

-- name: BulkUpdateVerificationStatus :exec
UPDATE clinics
SET verification_status = $2, updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeactivateClinic :exec
UPDATE clinics
SET verification_status = 'rejected', 
    is_verified = FALSE,
    updated_at = NOW()
WHERE id = $1;

-- name: ReactivateClinic :exec
UPDATE clinics
SET verification_status = 'pending', 
    updated_at = NOW()
WHERE id = $1;

-- name: SearchClinicsAdvanced :many
SELECT id, clinic_name, clinic_type, city, province, 
    physical_address, primary_phone, rating, review_count
FROM clinics
WHERE 
    verification_status = 'verified'
    AND (
        clinic_name ILIKE '%' || $1 || '%'
        OR physical_address ILIKE '%' || $1 || '%'
        OR city ILIKE '%' || $1 || '%'
    )
    AND ($2::VARCHAR IS NULL OR province = $2)
    AND ($3::VARCHAR IS NULL OR city = $3)
    AND ($4::VARCHAR IS NULL OR clinic_type = $4)
    AND ($5::BOOLEAN IS NULL OR accepts_medical_aid = $5)
ORDER BY 
    CASE WHEN clinic_name ILIKE $1 THEN 1 ELSE 2 END,
    rating DESC NULLS LAST
LIMIT $6 OFFSET $7;

-- name: GetNearbyClinicsByService :many
SELECT 
    id, 
    clinic_name, 
    clinic_type, 
    physical_address, 
    city, 
    province, 
    primary_phone, 
    latitude, 
    longitude, 
    rating,
    services,
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
ORDER BY distance_km ASC;

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
