-- ============================================
-- PATIENT FAMILY HISTORY REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Family Medical History Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddFamilyHistory :one
INSERT INTO patient_family_history (
    patient_id, relative, relative_age_at_diagnosis, condition_name,
    notes, is_alive, cause_of_death, age_at_death
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetFamilyHistoryEntry :one
SELECT * FROM patient_family_history
WHERE id = $1;

-- name: UpdateFamilyHistory :exec
UPDATE patient_family_history
SET 
    relative = COALESCE($2, relative),
    relative_age_at_diagnosis = COALESCE($3, relative_age_at_diagnosis),
    condition_name = COALESCE($4, condition_name),
    notes = COALESCE($5, notes),
    is_alive = COALESCE($6, is_alive),
    cause_of_death = COALESCE($7, cause_of_death),
    age_at_death = COALESCE($8, age_at_death)
WHERE id = $1;

-- name: DeleteFamilyHistory :exec
DELETE FROM patient_family_history WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientFamilyHistory :many
SELECT 
    id, patient_id, relative, relative_age_at_diagnosis,
    condition_name, notes, is_alive, cause_of_death,
    age_at_death, created_at
FROM patient_family_history
WHERE patient_id = $1
ORDER BY relative, condition_name;

-- name: GetFamilyHistoryByRelative :many
SELECT 
    id, condition_name, relative_age_at_diagnosis,
    is_alive, cause_of_death, age_at_death, notes
FROM patient_family_history
WHERE 
    patient_id = $1
    AND relative = $2
ORDER BY condition_name;

-- name: GetFamilyHistoryByCondition :many
SELECT 
    id, relative, relative_age_at_diagnosis, notes
FROM patient_family_history
WHERE 
    patient_id = $1
    AND condition_name ILIKE '%' || $2 || '%'
ORDER BY relative;

-- ============================================
-- GENETIC RISK ASSESSMENT
-- ============================================

-- name: GetGeneticConditions :many
SELECT 
    condition_name,
    COUNT(*) as affected_relatives,
    STRING_AGG(relative, ', ') as relatives,
    AVG(relative_age_at_diagnosis) FILTER (WHERE relative_age_at_diagnosis IS NOT NULL) as avg_onset_age
FROM patient_family_history
WHERE patient_id = $1
GROUP BY condition_name
HAVING COUNT(*) > 1
ORDER BY affected_relatives DESC;

-- name: GetHeritableConditions :many
SELECT 
    condition_name,
    relative,
    relative_age_at_diagnosis
FROM patient_family_history
WHERE 
    patient_id = $1
    AND relative IN ('mother', 'father', 'sibling')
ORDER BY condition_name, relative;

-- name: GetPatientsWithFamilyCondition :many
SELECT 
    pfh.patient_id,
    pp.first_name,
    pp.last_name,
    pfh.relative,
    pfh.relative_age_at_diagnosis
FROM patient_family_history pfh
JOIN patient_profiles pp ON pfh.patient_id = pp.id
WHERE pfh.condition_name ILIKE '%' || $1 || '%'
ORDER BY pp.last_name;

-- ============================================
-- MORTALITY TRACKING
-- ============================================

-- name: GetDeceasedRelatives :many
SELECT 
    relative, cause_of_death, age_at_death, condition_name
FROM patient_family_history
WHERE 
    patient_id = $1
    AND is_alive = false
ORDER BY age_at_death ASC NULLS LAST;

-- name: GetEarlyDeaths :many
SELECT 
    pfh.patient_id,
    pp.first_name,
    pp.last_name,
    pfh.relative,
    pfh.age_at_death,
    pfh.cause_of_death
FROM patient_family_history pfh
JOIN patient_profiles pp ON pfh.patient_id = pp.id
WHERE 
    pfh.is_alive = false
    AND pfh.age_at_death < $1
ORDER BY pfh.age_at_death ASC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountFamilyHistoryEntries :one
SELECT 
    COUNT(*) as total_entries,
    COUNT(DISTINCT relative) as unique_relatives,
    COUNT(DISTINCT condition_name) as unique_conditions,
    COUNT(*) FILTER (WHERE is_alive = false) as deceased_relatives
FROM patient_family_history
WHERE patient_id = $1;

-- name: GetFamilyHistoryStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_with_family_history,
    COUNT(*) as total_entries,
    COUNT(DISTINCT condition_name) as unique_conditions,
    COUNT(*) FILTER (WHERE is_alive = false) as deceased_count,
    AVG(age_at_death) FILTER (WHERE age_at_death IS NOT NULL) as avg_age_at_death
FROM patient_family_history;

-- name: GetMostCommonFamilyConditions :many
SELECT 
    condition_name,
    COUNT(*) as occurrence_count,
    COUNT(DISTINCT patient_id) as patient_count,
    AVG(relative_age_at_diagnosis) FILTER (WHERE relative_age_at_diagnosis IS NOT NULL) as avg_onset_age
FROM patient_family_history
GROUP BY condition_name
ORDER BY occurrence_count DESC
LIMIT $1;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetFamilyHistoryByPatientIDs :many
SELECT 
    patient_id, relative, condition_name, is_alive
FROM patient_family_history
WHERE patient_id = ANY($1::uuid[])
ORDER BY patient_id, relative, condition_name;

-- name: DeletePatientFamilyHistory :exec
DELETE FROM patient_family_history
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: HasFamilyHistory :one
SELECT EXISTS(
    SELECT 1 FROM patient_family_history
    WHERE patient_id = $1
) as has_history;

-- name: HasConditionInFamily :one
SELECT EXISTS(
    SELECT 1 FROM patient_family_history
    WHERE 
        patient_id = $1
        AND condition_name ILIKE '%' || $2 || '%'
) as has_condition;

-- name: CountRelativesWithCondition :one
SELECT COUNT(*) as relative_count
FROM patient_family_history
WHERE 
    patient_id = $1
    AND condition_name ILIKE '%' || $2 || '%';