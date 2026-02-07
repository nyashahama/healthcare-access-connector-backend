-- ============================================
-- PATIENT IMMUNIZATIONS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Immunization & Vaccination Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientImmunization :one
INSERT INTO patient_immunizations (
    patient_id, vaccine_name, vaccine_type, administration_date,
    next_due_date, administered_by, clinic_name, lot_number,
    manufacturer, dose_number, total_doses, notes, documented_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING *;

-- name: GetPatientImmunization :one
SELECT * FROM patient_immunizations
WHERE id = $1;

-- name: UpdatePatientImmunization :exec
UPDATE patient_immunizations
SET 
    vaccine_name = COALESCE($2, vaccine_name),
    vaccine_type = COALESCE($3, vaccine_type),
    next_due_date = COALESCE($4, next_due_date),
    notes = COALESCE($5, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientImmunization :exec
DELETE FROM patient_immunizations WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientImmunizations :many
SELECT 
    id, patient_id, vaccine_name, vaccine_type, administration_date,
    next_due_date, administered_by, clinic_name, dose_number,
    total_doses, notes, created_at
FROM patient_immunizations
WHERE patient_id = $1
ORDER BY administration_date DESC;

-- ============================================
-- DUE DATE & SCHEDULING
-- ============================================

-- name: GetUpcomingImmunizations :many
SELECT 
    id, patient_id, vaccine_name, vaccine_type, next_due_date,
    dose_number, total_doses, notes
FROM patient_immunizations
WHERE 
    patient_id = $1
    AND next_due_date IS NOT NULL
    AND next_due_date >= CURRENT_DATE
ORDER BY next_due_date ASC;

