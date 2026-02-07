-- ============================================
-- PATIENT FAMILY HISTORY REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Family Medical History Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddFamilyHistory :one
INSERT INTO patient_family_history (
    patient_id, relative, relative_age_at_diagnosis, condition_name,
    notes, is_alive, cause_of_death, age_at_death
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetFamilyHistoryEntry :one
SELECT * FROM patient_family_history
WHERE id = $1;

-- name: UpdateFamilyHistory :exec
UPDATE patient_family_history
SET 
    relative = COALESCE($2, relative),
    relative_age_at_diagnosis = COALESCE($3, relative_age_at_diagnosis),
    condition_name = COALESCE($4, condition_name),
    notes = COALESCE($5, notes),
    is_alive = COALESCE($6, is_alive),
    cause_of_death = COALESCE($7, cause_of_death),
    age_at_death = COALESCE($8, age_at_death)
WHERE id = $1;

-- name: DeleteFamilyHistory :exec
DELETE FROM patient_family_history WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientFamilyHistory :many
SELECT 
    id, patient_id, relative, relative_age_at_diagnosis,
    condition_name, notes, is_alive, cause_of_death,
    age_at_death, created_at
FROM patient_family_history
WHERE patient_id = $1
ORDER BY relative, condition_name;

