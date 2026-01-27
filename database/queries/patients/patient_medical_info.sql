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

-- name: UpdatePatientVitals :exec
UPDATE patient_medical_info
SET 
    height_cm = $2,
    weight_kg = $3,
    bmi = $4,
    last_measured_date = $5,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdatePatientHeight :exec
UPDATE patient_medical_info
SET 
    height_cm = $2,
    last_measured_date = CURRENT_DATE,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdatePatientWeight :exec
UPDATE patient_medical_info
SET 
    weight_kg = $2,
    bmi = $3,
    last_measured_date = CURRENT_DATE,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdatePatientBMI :exec
UPDATE patient_medical_info
SET 
    bmi = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: RecordVitalMeasurement :exec
UPDATE patient_medical_info
SET 
    height_cm = COALESCE($2, height_cm),
    weight_kg = COALESCE($3, weight_kg),
    bmi = COALESCE($4, bmi),
    last_measured_date = CURRENT_DATE,
    updated_at = NOW()
WHERE patient_id = $1;

-- ============================================
-- BLOOD TYPE MANAGEMENT
-- ============================================

-- name: UpdatePatientBloodType :exec
UPDATE patient_medical_info
SET 
    blood_type = $2,
    blood_type_last_tested = $3,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdateBloodTypeTestDate :exec
UPDATE patient_medical_info
SET 
    blood_type_last_tested = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: GetPatientsByBloodType :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.blood_type,
    pmi.blood_type_last_tested,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.blood_type = $1
ORDER BY pp.last_name, pp.first_name;

-- name: GetPatientsNeedingBloodTypeTest :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.blood_type,
    pmi.blood_type_last_tested,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.blood_type IS NULL
    OR pmi.blood_type_last_tested IS NULL
    OR pmi.blood_type_last_tested < CURRENT_DATE - INTERVAL '5 years'
ORDER BY pmi.blood_type_last_tested ASC NULLS FIRST
LIMIT $1 OFFSET $2;

-- ============================================
-- HEALTH STATUS MANAGEMENT
-- ============================================

-- name: UpdatePatientHealthStatus :exec
UPDATE patient_medical_info
SET 
    overall_health_status = $2,
    health_summary = $3,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdateHealthSummary :exec
UPDATE patient_medical_info
SET 
    health_summary = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: GetPatientsByHealthStatus :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.overall_health_status,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.overall_health_status = $1
ORDER BY pp.last_name, pp.first_name
LIMIT $2 OFFSET $3;

-- ============================================
-- CARE PROVIDER MANAGEMENT
-- ============================================

-- name: UpdatePrimaryCareProvider :exec
UPDATE patient_medical_info
SET 
    primary_care_physician = $2,
    primary_clinic_id = $3,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdatePrimaryPhysician :exec
UPDATE patient_medical_info
SET 
    primary_care_physician = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdatePrimaryClinic :exec
UPDATE patient_medical_info
SET 
    primary_clinic_id = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: GetPatientsByPrimaryCarePhysician :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.primary_care_physician,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.primary_care_physician = $1
ORDER BY pp.last_name, pp.first_name;

-- name: GetPatientsByPrimaryClinic :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.primary_care_physician,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.primary_clinic_id = $1
ORDER BY pp.last_name, pp.first_name;

-- name: GetPatientsWithoutPrimaryCare :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pp.city,
    pp.province,
    pp.has_medical_aid
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.primary_care_physician IS NULL
    AND pmi.primary_clinic_id IS NULL
ORDER BY pp.province, pp.city, pp.last_name
LIMIT $1 OFFSET $2;

-- ============================================
-- ADVANCE DIRECTIVES & END-OF-LIFE
-- ============================================

-- name: UpdateOrganDonorStatus :exec
UPDATE patient_medical_info
SET 
    organ_donor = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdateAdvanceDirective :exec
UPDATE patient_medical_info
SET 
    advance_directive_exists = $2,
    advance_directive_url = $3,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdateDNRStatus :exec
UPDATE patient_medical_info
SET 
    dnr_status = $2,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdateEndOfLifePreferences :exec
UPDATE patient_medical_info
SET 
    organ_donor = $2,
    advance_directive_exists = $3,
    advance_directive_url = $4,
    dnr_status = $5,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: GetOrganDonors :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.blood_type,
    pp.date_of_birth,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.organ_donor = true
    AND ($1::VARCHAR IS NULL OR pmi.blood_type = $1)
    AND ($2::VARCHAR IS NULL OR pp.province = $2)
ORDER BY pp.province, pp.city, pp.last_name;

-- name: GetPatientsWithAdvanceDirectives :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.advance_directive_url,
    pp.date_of_birth
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.advance_directive_exists = true
ORDER BY pp.last_name, pp.first_name;

-- name: GetPatientsWithDNR :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pp.date_of_birth,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.dnr_status = true
ORDER BY pp.province, pp.city, pp.last_name;

-- ============================================
-- HEALTH METRICS & ANALYTICS
-- ============================================

-- name: GetBMIDistribution :many
SELECT 
    CASE
        WHEN bmi < 18.5 THEN 'Underweight'
        WHEN bmi >= 18.5 AND bmi < 25 THEN 'Normal'
        WHEN bmi >= 25 AND bmi < 30 THEN 'Overweight'
        WHEN bmi >= 30 THEN 'Obese'
        ELSE 'Unknown'
    END as bmi_category,
    COUNT(*) as patient_count,
    AVG(bmi) as avg_bmi
FROM patient_medical_info
WHERE bmi IS NOT NULL
GROUP BY bmi_category
ORDER BY 
    CASE bmi_category
        WHEN 'Underweight' THEN 1
        WHEN 'Normal' THEN 2
        WHEN 'Overweight' THEN 3
        WHEN 'Obese' THEN 4
        ELSE 5
    END;

-- name: GetHealthStatusDistribution :many
SELECT 
    overall_health_status,
    COUNT(*) as patient_count,
    AVG(bmi) FILTER (WHERE bmi IS NOT NULL) as avg_bmi
FROM patient_medical_info
WHERE overall_health_status IS NOT NULL
GROUP BY overall_health_status
ORDER BY 
    CASE overall_health_status
        WHEN 'excellent' THEN 1
        WHEN 'good' THEN 2
        WHEN 'fair' THEN 3
        WHEN 'poor' THEN 4
        ELSE 5
    END;

-- name: GetBloodTypeDistribution :many
SELECT 
    blood_type,
    COUNT(*) as patient_count,
    COUNT(*) FILTER (WHERE organ_donor = true) as organ_donors
FROM patient_medical_info
WHERE blood_type IS NOT NULL
GROUP BY blood_type
ORDER BY patient_count DESC;

-- name: GetMedicalInfoStatistics :one
SELECT 
    COUNT(*) as total_records,
    COUNT(*) FILTER (WHERE blood_type IS NOT NULL) as with_blood_type,
    COUNT(*) FILTER (WHERE height_cm IS NOT NULL) as with_height,
    COUNT(*) FILTER (WHERE weight_kg IS NOT NULL) as with_weight,
    COUNT(*) FILTER (WHERE bmi IS NOT NULL) as with_bmi,
    COUNT(*) FILTER (WHERE primary_care_physician IS NOT NULL) as with_primary_physician,
    COUNT(*) FILTER (WHERE primary_clinic_id IS NOT NULL) as with_primary_clinic,
    COUNT(*) FILTER (WHERE organ_donor = true) as organ_donors,
    COUNT(*) FILTER (WHERE dnr_status = true) as with_dnr,
    COUNT(*) FILTER (WHERE advance_directive_exists = true) as with_advance_directive,
    AVG(bmi) FILTER (WHERE bmi IS NOT NULL) as avg_bmi,
    AVG(weight_kg) FILTER (WHERE weight_kg IS NOT NULL) as avg_weight,
    AVG(height_cm) FILTER (WHERE height_cm IS NOT NULL) as avg_height
FROM patient_medical_info;

-- name: GetVitalStatisticsSummary :one
SELECT 
    COUNT(*) FILTER (WHERE height_cm IS NOT NULL AND weight_kg IS NOT NULL) as with_complete_vitals,
    COUNT(*) FILTER (WHERE last_measured_date >= CURRENT_DATE - INTERVAL '6 months') as recently_measured,
    COUNT(*) FILTER (WHERE last_measured_date < CURRENT_DATE - INTERVAL '1 year' OR last_measured_date IS NULL) as outdated_measurements,
    AVG(bmi) FILTER (WHERE bmi IS NOT NULL AND bmi > 0) as avg_bmi,
    MIN(last_measured_date) as oldest_measurement,
    MAX(last_measured_date) as most_recent_measurement
FROM patient_medical_info;

-- ============================================
-- COMPLETENESS & DATA QUALITY
-- ============================================

-- name: GetIncompleteMedicalInfo :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    CASE WHEN pmi.blood_type IS NULL THEN true ELSE false END as missing_blood_type,
    CASE WHEN pmi.height_cm IS NULL THEN true ELSE false END as missing_height,
    CASE WHEN pmi.weight_kg IS NULL THEN true ELSE false END as missing_weight,
    CASE WHEN pmi.overall_health_status IS NULL THEN true ELSE false END as missing_health_status,
    CASE WHEN pmi.primary_care_physician IS NULL AND pmi.primary_clinic_id IS NULL THEN true ELSE false END as missing_primary_care,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.blood_type IS NULL
    OR pmi.height_cm IS NULL
    OR pmi.weight_kg IS NULL
    OR pmi.overall_health_status IS NULL
    OR (pmi.primary_care_physician IS NULL AND pmi.primary_clinic_id IS NULL)
ORDER BY pp.last_name, pp.first_name
LIMIT $1 OFFSET $2;

-- name: GetPatientsWithOutdatedVitals :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.last_measured_date,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.last_measured_date < CURRENT_DATE - INTERVAL '1 year'
    OR pmi.last_measured_date IS NULL
ORDER BY pmi.last_measured_date ASC NULLS FIRST
LIMIT $1 OFFSET $2;

-- name: GetPatientsNeedingHealthAssessment :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.overall_health_status,
    pmi.last_measured_date,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.overall_health_status IN ('poor', 'fair')
    AND (pmi.last_measured_date < CURRENT_DATE - INTERVAL '3 months' OR pmi.last_measured_date IS NULL)
ORDER BY 
    CASE pmi.overall_health_status
        WHEN 'poor' THEN 1
        WHEN 'fair' THEN 2
        ELSE 3
    END,
    pmi.last_measured_date ASC NULLS FIRST
LIMIT $1 OFFSET $2;

-- ============================================
-- BMI & WEIGHT MANAGEMENT QUERIES
-- ============================================

-- name: GetOverweightPatients :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.bmi,
    pmi.weight_kg,
    pmi.height_cm,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.bmi >= 25
    AND pmi.bmi < 30
ORDER BY pmi.bmi DESC
LIMIT $1 OFFSET $2;

-- name: GetObesePatients :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.bmi,
    pmi.weight_kg,
    pmi.height_cm,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.bmi >= 30
ORDER BY pmi.bmi DESC
LIMIT $1 OFFSET $2;

-- name: GetUnderweightPatients :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.bmi,
    pmi.weight_kg,
    pmi.height_cm,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.bmi < 18.5
ORDER BY pmi.bmi ASC
LIMIT $1 OFFSET $2;

-- name: GetPatientsByBMIRange :many
SELECT 
    pmi.patient_id,
    pp.first_name,
    pp.last_name,
    pmi.bmi,
    pp.city,
    pp.province
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE 
    pmi.bmi >= $1
    AND pmi.bmi <= $2
ORDER BY pmi.bmi DESC
LIMIT $3 OFFSET $4;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetMedicalInfoByPatientIDs :many
SELECT * FROM patient_medical_info
WHERE patient_id = ANY($1::uuid[])
ORDER BY patient_id;

-- name: BulkUpdateHealthStatus :exec
UPDATE patient_medical_info
SET 
    overall_health_status = $2,
    updated_at = NOW()
WHERE patient_id = ANY($1::uuid[]);

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: MedicalInfoExists :one
SELECT EXISTS(
    SELECT 1 FROM patient_medical_info WHERE patient_id = $1
) as exists;

-- name: HasCompleteVitals :one
SELECT 
    (height_cm IS NOT NULL AND weight_kg IS NOT NULL AND bmi IS NOT NULL) as has_complete_vitals
FROM patient_medical_info
WHERE patient_id = $1;

-- name: NeedsBMICalculation :many
SELECT 
    patient_id,
    height_cm,
    weight_kg
FROM patient_medical_info
WHERE 
    height_cm IS NOT NULL
    AND weight_kg IS NOT NULL
    AND (bmi IS NULL OR bmi = 0);

-- ============================================
-- EMERGENCY INFORMATION
-- ============================================

-- name: GetEmergencyMedicalInfo :one
SELECT 
    pmi.blood_type,
    pmi.dnr_status,
    pmi.organ_donor,
    pmi.primary_care_physician,
    pmi.primary_clinic_id,
    pmi.overall_health_status,
    pp.first_name,
    pp.last_name,
    pp.date_of_birth
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.patient_id = $1;

-- name: GetCriticalPatientInfo :one
SELECT 
    pmi.blood_type,
    pmi.dnr_status,
    pmi.advance_directive_exists,
    pmi.primary_care_physician,
    pp.first_name,
    pp.last_name,
    pp.date_of_birth,
    pp.national_id_number
FROM patient_medical_info pmi
JOIN patient_profiles pp ON pmi.patient_id = pp.id
WHERE pmi.patient_id = $1;
