-- ============================================
-- PATIENT SURGERIES REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Surgical History Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientSurgery :one
INSERT INTO patient_surgeries (
    patient_id, procedure_name, procedure_date, hospital_name,
    surgeon_name, anesthesia_type, complications, recovery_notes, outcome
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetPatientSurgery :one
SELECT * FROM patient_surgeries
WHERE id = $1;

-- name: UpdatePatientSurgery :exec
UPDATE patient_surgeries
SET 
    procedure_name = COALESCE($2, procedure_name),
    procedure_date = COALESCE($3, procedure_date),
    hospital_name = COALESCE($4, hospital_name),
    surgeon_name = COALESCE($5, surgeon_name),
    complications = COALESCE($6, complications),
    recovery_notes = COALESCE($7, recovery_notes),
    outcome = COALESCE($8, outcome),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientSurgery :exec
DELETE FROM patient_surgeries WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientSurgeries :many
SELECT 
    id, patient_id, procedure_name, procedure_date, hospital_name,
    surgeon_name, anesthesia_type, complications, recovery_notes,
    outcome, created_at, updated_at
FROM patient_surgeries
WHERE patient_id = $1
ORDER BY procedure_date DESC;

-- name: GetRecentSurgeries :many
SELECT 
    id, procedure_name, procedure_date, hospital_name,
    surgeon_name, outcome
FROM patient_surgeries
WHERE 
    patient_id = $1
    AND procedure_date >= CURRENT_DATE - INTERVAL '5 years'
ORDER BY procedure_date DESC;

-- name: GetSurgeriesWithComplications :many
SELECT 
    id, procedure_name, procedure_date, complications, outcome
FROM patient_surgeries
WHERE 
    patient_id = $1
    AND complications IS NOT NULL
ORDER BY procedure_date DESC;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchSurgeriesByProcedure :many
SELECT 
    id, procedure_name, procedure_date, hospital_name, surgeon_name, outcome
FROM patient_surgeries
WHERE 
    patient_id = $1
    AND procedure_name ILIKE '%' || $2 || '%'
ORDER BY procedure_date DESC;

-- name: GetPatientsByProcedure :many
SELECT 
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    ps.procedure_date,
    ps.hospital_name,
    ps.outcome
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
WHERE ps.procedure_name ILIKE '%' || $1 || '%'
ORDER BY ps.procedure_date DESC;

-- name: GetSurgeriesBySurgeon :many
SELECT 
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    ps.procedure_name,
    ps.procedure_date,
    ps.outcome
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
WHERE ps.surgeon_name = $1
ORDER BY ps.procedure_date DESC;

-- name: GetSurgeriesByHospital :many
SELECT 
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    ps.procedure_name,
    ps.procedure_date,
    ps.surgeon_name,
    ps.outcome
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
WHERE ps.hospital_name = $1
ORDER BY ps.procedure_date DESC;

-- ============================================
-- OUTCOME & COMPLICATIONS
-- ============================================

-- name: UpdateSurgeryOutcome :exec
UPDATE patient_surgeries
SET 
    outcome = $2,
    recovery_notes = COALESCE($3, recovery_notes),
    updated_at = NOW()
WHERE id = $1;

-- name: RecordComplications :exec
UPDATE patient_surgeries
SET 
    complications = $2,
    outcome = COALESCE($3, outcome),
    updated_at = NOW()
WHERE id = $1;

-- name: GetSurgeriesByOutcome :many
SELECT 
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    ps.procedure_name,
    ps.procedure_date,
    ps.complications
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
WHERE ps.outcome = $1
ORDER BY ps.procedure_date DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientSurgeries :one
SELECT 
    COUNT(*) as total_surgeries,
    COUNT(*) FILTER (WHERE complications IS NOT NULL) as with_complications,
    COUNT(*) FILTER (WHERE outcome = 'successful') as successful,
    COUNT(*) FILTER (WHERE outcome = 'complications') as with_outcome_complications,
    MAX(procedure_date) as last_surgery_date
FROM patient_surgeries
WHERE patient_id = $1;

-- name: GetSurgeryStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_with_surgeries,
    COUNT(*) as total_surgeries,
    COUNT(*) FILTER (WHERE outcome = 'successful') as successful_surgeries,
    COUNT(*) FILTER (WHERE complications IS NOT NULL) as surgeries_with_complications,
    COUNT(DISTINCT procedure_name) as unique_procedures,
    COUNT(DISTINCT hospital_name) as hospitals_used,
    AVG(EXTRACT(YEAR FROM AGE(CURRENT_DATE, procedure_date))) FILTER (WHERE procedure_date IS NOT NULL) as avg_years_since_surgery
FROM patient_surgeries;

-- name: GetMostCommonProcedures :many
SELECT 
    procedure_name,
    COUNT(DISTINCT patient_id) as patient_count,
    COUNT(*) as total_procedures,
    COUNT(*) FILTER (WHERE outcome = 'successful') as successful_count,
    COUNT(*) FILTER (WHERE complications IS NOT NULL) as complication_count
FROM patient_surgeries
GROUP BY procedure_name
ORDER BY patient_count DESC
LIMIT $1;

-- name: GetSurgeryTrends :many
SELECT 
    DATE_TRUNC('year', procedure_date) as year,
    COUNT(*) as surgery_count,
    COUNT(DISTINCT patient_id) as unique_patients,
    COUNT(DISTINCT procedure_name) as unique_procedures
FROM patient_surgeries
WHERE procedure_date >= $1
GROUP BY DATE_TRUNC('year', procedure_date)
ORDER BY year DESC;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetSurgeriesByPatientIDs :many
SELECT 
    patient_id, procedure_name, procedure_date, outcome
FROM patient_surgeries
WHERE patient_id = ANY($1::uuid[])
ORDER BY patient_id, procedure_date DESC;

-- name: DeletePatientSurgeries :exec
DELETE FROM patient_surgeries
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: HasSurgicalHistory :one
SELECT EXISTS(
    SELECT 1 FROM patient_surgeries
    WHERE patient_id = $1
) as has_history;

-- name: GetLastSurgeryDate :one
SELECT MAX(procedure_date) as last_surgery_date
FROM patient_surgeries
WHERE patient_id = $1;

-- ============================================
-- REPORTING QUERIES
-- ============================================

-- name: GetPatientsWithMultipleSurgeries :many
SELECT 
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    COUNT(*) as surgery_count,
    MAX(ps.procedure_date) as last_surgery_date
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
GROUP BY ps.patient_id, pp.first_name, pp.last_name
HAVING COUNT(*) >= $1
ORDER BY surgery_count DESC;

-- name: GetRecentSurgicalPatients :many
SELECT 
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    ps.procedure_name,
    ps.procedure_date,
    ps.hospital_name,
    ps.outcome
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
WHERE ps.procedure_date >= $1
ORDER BY ps.procedure_date DESC;

-- name: GetSurgeriesByDateRange :many
SELECT 
    ps.id,
    ps.patient_id,
    pp.first_name,
    pp.last_name,
    ps.procedure_name,
    ps.procedure_date,
    ps.hospital_name,
    ps.outcome
FROM patient_surgeries ps
JOIN patient_profiles pp ON ps.patient_id = pp.id
WHERE ps.procedure_date BETWEEN $1 AND $2
ORDER BY ps.procedure_date DESC;

-- name: GetEmergencySurgeryInfo :many
SELECT 
    procedure_name,
    procedure_date,
    hospital_name,
    surgeon_name,
    complications,
    outcome
FROM patient_surgeries
WHERE patient_id = $1
ORDER BY procedure_date DESC;