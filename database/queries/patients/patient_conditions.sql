-- ============================================
-- Patient Conditions Queries
-- ============================================

-- name: AddPatientCondition :one
INSERT INTO patient_conditions (
    patient_id, condition_name, icd10_code, type, diagnosed_date, 
    diagnosed_by, severity, status, notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, patient_id, condition_name, type, status, created_at;


-- name: GetPatientConditions :many
SELECT id, patient_id, condition_name, icd10_code, type, 
    diagnosed_date, diagnosed_by, severity, status, notes,
    last_flare_up, next_checkup_date, created_at, updated_at
FROM patient_conditions
WHERE patient_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY diagnosed_date DESC;


-- name: UpdatePatientCondition :exec
UPDATE patient_conditions
SET condition_name = $2, severity = $3, status = $4, 
    notes = $5, last_flare_up = $6, next_checkup_date = $7
WHERE id = $1;

