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

-- name: GetImmunizationHistory :many
SELECT 
    vaccine_name, vaccine_type, administration_date,
    dose_number, total_doses, administered_by, clinic_name
FROM patient_immunizations
WHERE patient_id = $1
ORDER BY administration_date DESC;

-- name: GetImmunizationsByType :many
SELECT 
    id, vaccine_name, administration_date, next_due_date,
    dose_number, total_doses, administered_by
FROM patient_immunizations
WHERE 
    patient_id = $1
    AND vaccine_type = $2
ORDER BY administration_date DESC;

-- name: GetRoutineImmunizations :many
SELECT 
    id, vaccine_name, administration_date, next_due_date, dose_number, total_doses
FROM patient_immunizations
WHERE 
    patient_id = $1
    AND vaccine_type = 'routine'
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

-- name: GetOverdueImmunizations :many
SELECT 
    pi.id,
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.vaccine_name,
    pi.next_due_date,
    pi.dose_number,
    pi.total_doses
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE 
    pi.next_due_date < CURRENT_DATE
ORDER BY pi.next_due_date ASC;

-- name: GetImmunizationsDueInPeriod :many
SELECT 
    pi.id,
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.vaccine_name,
    pi.vaccine_type,
    pi.next_due_date,
    pi.dose_number,
    pi.total_doses
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE 
    pi.next_due_date BETWEEN CURRENT_DATE AND $1
ORDER BY pi.next_due_date ASC;

-- name: UpdateNextDueDate :exec
UPDATE patient_immunizations
SET 
    next_due_date = $2,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- VACCINE SERIES TRACKING
-- ============================================

-- name: GetIncompleteVaccineSeries :many
SELECT 
    id, vaccine_name, dose_number, total_doses,
    administration_date, next_due_date
FROM patient_immunizations
WHERE 
    patient_id = $1
    AND dose_number < total_doses
ORDER BY next_due_date ASC NULLS LAST;

-- name: GetCompleteVaccineSeries :many
SELECT 
    vaccine_name,
    MAX(dose_number) as doses_completed,
    MAX(total_doses) as total_doses,
    MAX(administration_date) as last_dose_date
FROM patient_immunizations
WHERE patient_id = $1
GROUP BY vaccine_name
HAVING MAX(dose_number) >= MAX(total_doses);

-- name: GetVaccineSeriesProgress :many
SELECT 
    vaccine_name,
    MAX(dose_number) as current_dose,
    MAX(total_doses) as total_doses,
    CASE 
        WHEN MAX(dose_number) >= MAX(total_doses) THEN 'complete'
        ELSE 'incomplete'
    END as status,
    MAX(administration_date) as last_dose_date,
    MIN(next_due_date) FILTER (WHERE next_due_date >= CURRENT_DATE) as next_due
FROM patient_immunizations
WHERE patient_id = $1
GROUP BY vaccine_name
ORDER BY vaccine_name;

-- ============================================
-- VACCINE & PROVIDER QUERIES
-- ============================================

-- name: GetImmunizationsByVaccine :many
SELECT 
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.administration_date,
    pi.dose_number,
    pi.administered_by,
    pi.clinic_name
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE pi.vaccine_name = $1
ORDER BY pi.administration_date DESC;

-- name: GetImmunizationsByAdministrator :many
SELECT 
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.vaccine_name,
    pi.administration_date,
    pi.clinic_name
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE pi.administered_by = $1
ORDER BY pi.administration_date DESC;

-- name: GetImmunizationsByClinic :many
SELECT 
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.vaccine_name,
    pi.administration_date,
    pi.administered_by
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE pi.clinic_name = $1
ORDER BY pi.administration_date DESC;

-- name: GetImmunizationsByLotNumber :many
SELECT 
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.vaccine_name,
    pi.administration_date,
    pi.manufacturer
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE pi.lot_number = $1
ORDER BY pi.administration_date DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientImmunizations :one
SELECT 
    COUNT(*) as total_immunizations,
    COUNT(DISTINCT vaccine_name) as unique_vaccines,
    COUNT(*) FILTER (WHERE vaccine_type = 'routine') as routine_count,
    COUNT(*) FILTER (WHERE next_due_date >= CURRENT_DATE) as upcoming_count,
    COUNT(*) FILTER (WHERE next_due_date < CURRENT_DATE) as overdue_count
FROM patient_immunizations
WHERE patient_id = $1;

-- name: GetImmunizationStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_immunized,
    COUNT(*) as total_immunizations,
    COUNT(DISTINCT vaccine_name) as unique_vaccines,
    COUNT(*) FILTER (WHERE vaccine_type = 'routine') as routine_immunizations,
    COUNT(*) FILTER (WHERE vaccine_type = 'covid') as covid_immunizations,
    COUNT(*) FILTER (WHERE vaccine_type = 'flu') as flu_immunizations,
    COUNT(*) FILTER (WHERE next_due_date < CURRENT_DATE) as overdue_count,
    AVG(dose_number::NUMERIC / total_doses) FILTER (WHERE total_doses > 0) as avg_series_completion
FROM patient_immunizations;

-- name: GetVaccineDistribution :many
SELECT 
    vaccine_name,
    COUNT(DISTINCT patient_id) as patient_count,
    COUNT(*) as total_doses,
    AVG(dose_number::NUMERIC) as avg_dose_number
FROM patient_immunizations
GROUP BY vaccine_name
ORDER BY patient_count DESC;

-- name: GetImmunizationCoverage :many
SELECT 
    vaccine_type,
    COUNT(DISTINCT patient_id) as patients_vaccinated,
    COUNT(*) as total_doses,
    COUNT(*) FILTER (WHERE administration_date >= CURRENT_DATE - INTERVAL '1 year') as doses_last_year
FROM patient_immunizations
GROUP BY vaccine_type
ORDER BY patients_vaccinated DESC;

-- ============================================
-- COMPLIANCE & REPORTING
-- ============================================

-- name: GetPatientsNeedingImmunizations :many
SELECT DISTINCT
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pp.date_of_birth,
    COUNT(DISTINCT pi.vaccine_name) FILTER (WHERE pi.next_due_date < CURRENT_DATE) as overdue_count,
    pp.city,
    pp.province
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE pi.next_due_date < CURRENT_DATE
GROUP BY pi.patient_id, pp.first_name, pp.last_name, pp.date_of_birth, pp.city, pp.province
ORDER BY overdue_count DESC, pp.last_name;

-- name: GetChildrenNeedingVaccines :many
SELECT 
    pp.id as patient_id,
    pp.first_name,
    pp.last_name,
    pp.date_of_birth,
    EXTRACT(YEAR FROM AGE(pp.date_of_birth))::INTEGER as age_years,
    pp.city,
    pp.province
FROM patient_profiles pp
LEFT JOIN patient_immunizations pi ON pp.id = pi.patient_id AND pi.vaccine_type = 'routine'
WHERE 
    pp.date_of_birth > CURRENT_DATE - INTERVAL '18 years'
    AND pi.id IS NULL
ORDER BY pp.date_of_birth DESC
LIMIT $1 OFFSET $2;

-- name: GetImmunizationRecordsByDateRange :many
SELECT 
    pi.id,
    pi.patient_id,
    pp.first_name,
    pp.last_name,
    pi.vaccine_name,
    pi.administration_date,
    pi.administered_by,
    pi.clinic_name
FROM patient_immunizations pi
JOIN patient_profiles pp ON pi.patient_id = pp.id
WHERE 
    pi.administration_date BETWEEN $1 AND $2
ORDER BY pi.administration_date DESC;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetImmunizationsByPatientIDs :many
SELECT 
    patient_id, vaccine_name, vaccine_type,
    administration_date, next_due_date
FROM patient_immunizations
WHERE patient_id = ANY($1::uuid[])
ORDER BY patient_id, administration_date DESC;

-- name: DeletePatientImmunizations :exec
DELETE FROM patient_immunizations
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: CheckVaccineReceived :one
SELECT EXISTS(
    SELECT 1 FROM patient_immunizations
    WHERE 
        patient_id = $1
        AND vaccine_name = $2
) as has_received;

-- name: GetLastVaccineDate :one
SELECT MAX(administration_date) as last_vaccine_date
FROM patient_immunizations
WHERE 
    patient_id = $1
    AND vaccine_name = $2;

-- name: IsVaccineSeriesComplete :one
SELECT 
    CASE 
        WHEN MAX(dose_number) >= MAX(total_doses) THEN true
        ELSE false
    END as is_complete
FROM patient_immunizations
WHERE 
    patient_id = $1
    AND vaccine_name = $2;

-- ============================================
-- EMERGENCY ACCESS
-- ============================================

-- name: GetEmergencyImmunizationInfo :many
SELECT 
    vaccine_name,
    vaccine_type,
    administration_date,
    dose_number,
    total_doses
FROM patient_immunizations
WHERE patient_id = $1
ORDER BY administration_date DESC
LIMIT 10;
