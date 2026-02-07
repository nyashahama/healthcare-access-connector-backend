-- ============================================
-- PATIENT MEDICATIONS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Medication Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientMedication :one
INSERT INTO patient_medications (
    patient_id, medication_name, generic_name, dosage, frequency,
    route, prescribing_doctor, pharmacy_name, prescription_date,
    start_date, end_date, reason_for_medication, status,
    side_effects, instructions
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: GetPatientMedication :one
SELECT * FROM patient_medications
WHERE id = $1;

-- name: UpdatePatientMedication :exec
UPDATE patient_medications
SET 
    medication_name = COALESCE($2, medication_name),
    generic_name = COALESCE($3, generic_name),
    dosage = COALESCE($4, dosage),
    frequency = COALESCE($5, frequency),
    route = COALESCE($6, route),
    end_date = COALESCE($7, end_date),
    status = COALESCE($8, status),
    side_effects = COALESCE($9, side_effects),
    instructions = COALESCE($10, instructions),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientMedication :exec
DELETE FROM patient_medications WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientMedications :many
SELECT 
    id, patient_id, medication_name, generic_name, dosage,
    frequency, route, prescribing_doctor, start_date, end_date,
    reason_for_medication, status, instructions, side_effects,
    created_at, updated_at
FROM patient_medications
WHERE 
    patient_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY 
    CASE status
        WHEN 'active' THEN 1
        WHEN 'completed' THEN 2
        WHEN 'discontinued' THEN 3
        ELSE 4
    END,
    start_date DESC;

-- name: GetActiveMedications :many
SELECT 
    id, medication_name, generic_name, dosage, frequency,
    route, prescribing_doctor, start_date, reason_for_medication, instructions
FROM patient_medications
WHERE 
    patient_id = $1
    AND status = 'active'
ORDER BY start_date DESC;

