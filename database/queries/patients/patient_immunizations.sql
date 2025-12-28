-- ============================================
-- Patient Immunizations Queries
-- ============================================

-- name: AddPatientImmunization :one
INSERT INTO patient_immunizations (
    patient_id, vaccine_name, vaccine_type, administration_date, 
    next_due_date, administered_by, clinic_name, lot_number, 
    manufacturer, dose_number, total_doses, documented_by
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id, patient_id, vaccine_name, administration_date, next_due_date, created_at;


-- name: GetPatientImmunizations :many
SELECT id, patient_id, vaccine_name, vaccine_type, administration_date,
    next_due_date, administered_by, clinic_name, dose_number, 
    total_doses, notes, created_at
FROM patient_immunizations
WHERE patient_id = $1
ORDER BY administration_date DESC;


-- name: GetUpcomingImmunizations :many
SELECT id, patient_id, vaccine_name, vaccine_type, next_due_date,
    dose_number, total_doses
FROM patient_immunizations
WHERE patient_id = $1 
    AND next_due_date IS NOT NULL 
    AND next_due_date > NOW()
ORDER BY next_due_date ASC;


