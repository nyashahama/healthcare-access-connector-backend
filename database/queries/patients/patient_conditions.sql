-- ============================================
-- PATIENT CONDITIONS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Medical Conditions Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientCondition :one
INSERT INTO patient_conditions (
    patient_id, condition_name, icd10_code, type, diagnosed_date,
    diagnosed_by, severity, status, notes, last_flare_up, next_checkup_date
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetPatientCondition :one
SELECT * FROM patient_conditions
WHERE id = $1;

-- name: UpdatePatientCondition :exec
UPDATE patient_conditions
SET 
    condition_name = COALESCE($2, condition_name),
    icd10_code = COALESCE($3, icd10_code),
    severity = COALESCE($4, severity),
    status = COALESCE($5, status),
    notes = COALESCE($6, notes),
    last_flare_up = COALESCE($7, last_flare_up),
    next_checkup_date = COALESCE($8, next_checkup_date),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientCondition :exec
DELETE FROM patient_conditions WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientConditions :many
SELECT 
    id, patient_id, condition_name, icd10_code, type,
    diagnosed_date, diagnosed_by, severity, status, notes,
    last_flare_up, next_checkup_date, created_at, updated_at
FROM patient_conditions
WHERE 
    patient_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY 
    CASE status
        WHEN 'active' THEN 1
        WHEN 'managed' THEN 2
        WHEN 'remission' THEN 3
        WHEN 'resolved' THEN 4
        ELSE 5
    END,
    diagnosed_date DESC;

-- name: GetActiveConditions :many
SELECT 
    id, condition_name, type, severity, diagnosed_date,
    last_flare_up, next_checkup_date
FROM patient_conditions
WHERE 
    patient_id = $1
    AND status = 'active'
ORDER BY severity DESC, diagnosed_date DESC;
