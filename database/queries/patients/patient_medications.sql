-- ============================================
-- Patient Medications Queries
-- ============================================

-- name: AddPatientMedication :one
INSERT INTO patient_medications (
    patient_id, medication_name, generic_name, dosage, frequency, 
    route, prescribing_doctor, pharmacy_name, prescription_date, 
    start_date, end_date, reason_for_medication, status, instructions
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING id, patient_id, medication_name, dosage, frequency, status, created_at;


-- name: GetPatientMedications :many
SELECT id, patient_id, medication_name, generic_name, dosage, 
    frequency, route, prescribing_doctor, start_date, end_date,
    reason_for_medication, status, instructions, created_at, updated_at
FROM patient_medications
WHERE patient_id = $1 
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY start_date DESC;


-- name: UpdatePatientMedication :exec
UPDATE patient_medications
SET medication_name = $2, dosage = $3, frequency = $4, 
    route = $5, end_date = $6, status = $7, 
    side_effects = $8, instructions = $9
WHERE id = $1;
