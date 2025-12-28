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

