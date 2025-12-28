-- ============================================
-- Patient Allergies Queries
-- ============================================

-- name: AddPatientAllergy :one
INSERT INTO patient_allergies (
    patient_id, allergy_name, severity, reaction_description, 
    first_identified_date, status, notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, patient_id, allergy_name, severity, status, created_at;

-- name: GetPatientAllergies :many
SELECT id, patient_id, allergy_name, severity, reaction_description,
    first_identified_date, last_occurrence_date, status, notes, 
    created_at, updated_at
FROM patient_allergies
WHERE patient_id = $1
ORDER BY severity DESC, created_at DESC;


-- name: UpdatePatientAllergy :exec
UPDATE patient_allergies
SET allergy_name = $2, severity = $3, reaction_description = $4,
    last_occurrence_date = $5, status = $6, notes = $7
WHERE id = $1;


-- name: DeletePatientAllergy :exec
DELETE FROM patient_allergies WHERE id = $1;

