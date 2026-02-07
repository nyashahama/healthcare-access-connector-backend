-- ============================================
-- PATIENT DEPENDENTS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Dependent (Children/Wards) Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientDependent :one
INSERT INTO patient_dependents (
    patient_id, first_name, last_name, date_of_birth, gender, relationship,
    blood_type, health_status, primary_pediatrician, clinic_id,
    birth_weight_kg, birth_height_cm, school_name, grade,
    has_legal_guardianship, guardianship_document_url,
    has_special_needs, special_needs_description
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
RETURNING *;

-- name: GetPatientDependent :one
SELECT * FROM patient_dependents
WHERE id = $1;

-- name: UpdatePatientDependent :exec
UPDATE patient_dependents
SET 
    first_name = COALESCE($2, first_name),
    last_name = COALESCE($3, last_name),
    date_of_birth = COALESCE($4, date_of_birth),
    gender = COALESCE($5, gender),
    blood_type = COALESCE($6, blood_type),
    health_status = COALESCE($7, health_status),
    primary_pediatrician = COALESCE($8, primary_pediatrician),
    clinic_id = COALESCE($9, clinic_id),
    school_name = COALESCE($10, school_name),
    grade = COALESCE($11, grade),
    has_special_needs = COALESCE($12, has_special_needs),
    special_needs_description = COALESCE($13, special_needs_description),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientDependent :exec
DELETE FROM patient_dependents WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientDependents :many
SELECT 
    id, patient_id, first_name, last_name, date_of_birth,
    gender, relationship, blood_type, health_status,
    primary_pediatrician, school_name, grade,
    has_special_needs, created_at, updated_at
FROM patient_dependents
WHERE patient_id = $1
ORDER BY date_of_birth DESC;

-- name: GetDependentChildren :many
SELECT 
    id, first_name, last_name, date_of_birth, gender,
    health_status, school_name, grade
FROM patient_dependents
WHERE 
    patient_id = $1
    AND relationship = 'child'
ORDER BY date_of_birth DESC;


