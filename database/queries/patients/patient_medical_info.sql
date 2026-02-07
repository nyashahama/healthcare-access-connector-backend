-- ============================================
-- PATIENT MEDICAL INFO REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Medical & Health Information Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreatePatientMedicalInfo :one
INSERT INTO patient_medical_info (
    patient_id, blood_type, blood_type_last_tested, height_cm, weight_kg, bmi,
    last_measured_date, overall_health_status, health_summary,
    primary_care_physician, primary_clinic_id,
    organ_donor, advance_directive_exists, advance_directive_url, dnr_status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: GetPatientMedicalInfo :one
SELECT * FROM patient_medical_info
WHERE patient_id = $1;

-- name: GetPatientMedicalInfoByID :one
SELECT * FROM patient_medical_info
WHERE id = $1;

-- name: UpdatePatientMedicalInfo :exec
UPDATE patient_medical_info
SET 
    blood_type = COALESCE($2, blood_type),
    blood_type_last_tested = COALESCE($3, blood_type_last_tested),
    height_cm = COALESCE($4, height_cm),
    weight_kg = COALESCE($5, weight_kg),
    bmi = COALESCE($6, bmi),
    last_measured_date = COALESCE($7, last_measured_date),
    overall_health_status = COALESCE($8, overall_health_status),
    health_summary = COALESCE($9, health_summary),
    primary_care_physician = COALESCE($10, primary_care_physician),
    primary_clinic_id = COALESCE($11, primary_clinic_id),
    updated_at = NOW()
WHERE patient_id = $1;

-- name: DeletePatientMedicalInfo :exec
DELETE FROM patient_medical_info
WHERE patient_id = $1;

-- ============================================
-- VITAL STATISTICS MANAGEMENT
-- ============================================


