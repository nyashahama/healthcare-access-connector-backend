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
