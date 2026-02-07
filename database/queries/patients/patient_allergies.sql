-- ============================================
-- PATIENT ALLERGIES REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Allergy Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientAllergy :one
INSERT INTO patient_allergies (
    patient_id, allergy_name, severity, reaction_description,
    first_identified_date, last_occurrence_date, status, notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetPatientAllergy :one
SELECT * FROM patient_allergies
WHERE id = $1;

-- name: UpdatePatientAllergy :exec
UPDATE patient_allergies
SET 
    allergy_name = COALESCE($2, allergy_name),
    severity = COALESCE($3, severity),
    reaction_description = COALESCE($4, reaction_description),
    last_occurrence_date = COALESCE($5, last_occurrence_date),
    status = COALESCE($6, status),
    notes = COALESCE($7, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientAllergy :exec
DELETE FROM patient_allergies WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientAllergies :many
SELECT 
    id, patient_id, allergy_name, severity, reaction_description,
    first_identified_date, last_occurrence_date, status, notes,
    created_at, updated_at
FROM patient_allergies
WHERE patient_id = $1
ORDER BY 
    CASE severity
        WHEN 'life_threatening' THEN 1
        WHEN 'severe' THEN 2
        WHEN 'moderate' THEN 3
        WHEN 'mild' THEN 4
        ELSE 5
    END,
    created_at DESC;

-- name: GetActivePatientAllergies :many
SELECT 
    id, allergy_name, severity, reaction_description,
    first_identified_date, last_occurrence_date, notes
FROM patient_allergies
WHERE 
    patient_id = $1
    AND status = 'active'
ORDER BY 
    CASE severity
        WHEN 'life_threatening' THEN 1
        WHEN 'severe' THEN 2
        WHEN 'moderate' THEN 3
        WHEN 'mild' THEN 4
        ELSE 5
    END;

