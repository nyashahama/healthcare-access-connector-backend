-- ============================================
-- DEPENDENT HEALTH RECORDS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Dependent Health Records & Growth Tracking
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddDependentHealthRecord :one
INSERT INTO dependent_health_records (
    dependent_id, record_type, record_date, weight_kg, height_cm,
    head_circumference_cm, temperature_c, notes, provider_name,
    clinic_name, next_appointment_date, documents
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetDependentHealthRecord :one
SELECT * FROM dependent_health_records
WHERE id = $1;

-- name: UpdateDependentHealthRecord :exec
UPDATE dependent_health_records
SET 
    record_type = COALESCE($2, record_type),
    weight_kg = COALESCE($3, weight_kg),
    height_cm = COALESCE($4, height_cm),
    head_circumference_cm = COALESCE($5, head_circumference_cm),
    temperature_c = COALESCE($6, temperature_c),
    notes = COALESCE($7, notes),
    next_appointment_date = COALESCE($8, next_appointment_date)
WHERE id = $1;

-- name: DeleteDependentHealthRecord :exec
DELETE FROM dependent_health_records WHERE id = $1;

-- ============================================
-- QUERYING BY DEPENDENT
-- ============================================

-- name: GetDependentHealthRecords :many
SELECT 
    id, dependent_id, record_type, record_date, weight_kg,
    height_cm, head_circumference_cm, temperature_c, notes,
    provider_name, clinic_name, next_appointment_date, created_at
FROM dependent_health_records
WHERE dependent_id = $1
ORDER BY record_date DESC;

-- name: GetGrowthRecords :many
SELECT 
    id, record_date, weight_kg, height_cm, head_circumference_cm, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'growth_check'
ORDER BY record_date DESC;

