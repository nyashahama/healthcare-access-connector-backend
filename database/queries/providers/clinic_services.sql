-- ============================================
-- CLINIC SERVICES REPOSITORY QUERIES
-- Maps to: Part of ClinicRepository interface (service-related methods)
-- Domain: Healthcare Service Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateClinicService :one
INSERT INTO clinic_services (
    clinic_id, service_name, service_category, description,
    duration_minutes, preparation_instructions, follow_up_required, follow_up_days,
    minimum_age, maximum_age, gender_restriction, prerequisites,
    cost, cost_currency, is_covered_by_medical_aid, medical_aid_codes,
    is_active, available_days, requires_appointment, walk_in_allowed,
    provided_by_staff_ids
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17, $18, $19, $20, $21
)
RETURNING *;

-- name: GetServiceByID :one
SELECT * FROM clinic_services
WHERE id = $1;

-- name: UpdateClinicService :exec
UPDATE clinic_services
SET 
    service_name = COALESCE($2, service_name),
    service_category = COALESCE($3, service_category),
    description = COALESCE($4, description),
    duration_minutes = COALESCE($5, duration_minutes),
    cost = COALESCE($6, cost),
    is_covered_by_medical_aid = COALESCE($7, is_covered_by_medical_aid),
    requires_appointment = COALESCE($8, requires_appointment),
    walk_in_allowed = COALESCE($9, walk_in_allowed),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteClinicService :exec
DELETE FROM clinic_services 
WHERE id = $1;

-- ============================================
-- QUERYING BY CLINIC
-- ============================================

-- name: GetClinicServices :many
SELECT 
    id, clinic_id, service_name, service_category, description,
    duration_minutes, cost, cost_currency, is_covered_by_medical_aid,
    is_active, requires_appointment, walk_in_allowed,
    average_rating, review_count, popularity_score
FROM clinic_services
WHERE clinic_id = $1 
ORDER BY popularity_score DESC, service_name ASC;

-- name: GetActiveClinicServices :many
SELECT 
    id, clinic_id, service_name, service_category, description,
    duration_minutes, cost, cost_currency, is_covered_by_medical_aid,
    requires_appointment, walk_in_allowed,
    average_rating, review_count, popularity_score
FROM clinic_services
WHERE 
    clinic_id = $1 
    AND is_active = TRUE
ORDER BY popularity_score DESC, service_name ASC;

-- name: ServiceExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_services 
    WHERE id = $1
) as exists;

-- name: CheckServiceNameExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_services
    WHERE 
        clinic_id = $1
        AND service_name = $2
        AND ($3::uuid IS NULL OR id != $3)
) as exists;

