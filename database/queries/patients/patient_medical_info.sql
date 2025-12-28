-- ============================================
-- Patient Medical Info Queries
-- ============================================

-- name: CreatePatientMedicalInfo :one
INSERT INTO patient_medical_info (
    patient_id, blood_type, height_cm, weight_kg, bmi, 
    overall_health_status, health_summary, primary_care_physician, 
    primary_clinic_id, organ_donor, dnr_status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING id, patient_id, blood_type, overall_health_status, created_at, updated_at;


-- name: GetPatientMedicalInfo :one
SELECT * FROM patient_medical_info WHERE patient_id = $1;


-- name: UpdatePatientMedicalInfo :exec
UPDATE patient_medical_info
SET blood_type = $2, height_cm = $3, weight_kg = $4, bmi = $5,
    overall_health_status = $6, health_summary = $7, 
    primary_care_physician = $8, primary_clinic_id = $9,
    last_measured_date = $10
WHERE patient_id = $1;

