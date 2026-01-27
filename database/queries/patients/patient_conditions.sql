-- ============================================
-- PATIENT CONDITIONS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Medical Conditions Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientCondition :one
INSERT INTO patient_conditions (
    patient_id, condition_name, icd10_code, type, diagnosed_date,
    diagnosed_by, severity, status, notes, last_flare_up, next_checkup_date
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetPatientCondition :one
SELECT * FROM patient_conditions
WHERE id = $1;

-- name: UpdatePatientCondition :exec
UPDATE patient_conditions
SET 
    condition_name = COALESCE($2, condition_name),
    icd10_code = COALESCE($3, icd10_code),
    severity = COALESCE($4, severity),
    status = COALESCE($5, status),
    notes = COALESCE($6, notes),
    last_flare_up = COALESCE($7, last_flare_up),
    next_checkup_date = COALESCE($8, next_checkup_date),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientCondition :exec
DELETE FROM patient_conditions WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientConditions :many
SELECT 
    id, patient_id, condition_name, icd10_code, type,
    diagnosed_date, diagnosed_by, severity, status, notes,
    last_flare_up, next_checkup_date, created_at, updated_at
FROM patient_conditions
WHERE 
    patient_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY 
    CASE status
        WHEN 'active' THEN 1
        WHEN 'managed' THEN 2
        WHEN 'remission' THEN 3
        WHEN 'resolved' THEN 4
        ELSE 5
    END,
    diagnosed_date DESC;

-- name: GetActiveConditions :many
SELECT 
    id, condition_name, type, severity, diagnosed_date,
    last_flare_up, next_checkup_date
FROM patient_conditions
WHERE 
    patient_id = $1
    AND status = 'active'
ORDER BY severity DESC, diagnosed_date DESC;

-- name: GetChronicConditions :many
SELECT 
    id, condition_name, icd10_code, diagnosed_date,
    severity, status, last_flare_up
FROM patient_conditions
WHERE 
    patient_id = $1
    AND type = 'chronic'
ORDER BY severity DESC, diagnosed_date DESC;

-- name: GetAcuteConditions :many
SELECT 
    id, condition_name, diagnosed_date, severity, status
FROM patient_conditions
WHERE 
    patient_id = $1
    AND type = 'acute'
ORDER BY diagnosed_date DESC;

-- name: GetConditionsByType :many
SELECT 
    id, condition_name, severity, status, diagnosed_date
FROM patient_conditions
WHERE 
    patient_id = $1
    AND type = $2
ORDER BY diagnosed_date DESC;

-- ============================================
-- STATUS MANAGEMENT
-- ============================================

-- name: UpdateConditionStatus :exec
UPDATE patient_conditions
SET 
    status = $2,
    notes = COALESCE($3, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: MarkConditionResolved :exec
UPDATE patient_conditions
SET 
    status = 'resolved',
    notes = COALESCE($2, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: MarkConditionInRemission :exec
UPDATE patient_conditions
SET 
    status = 'remission',
    notes = COALESCE($2, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateConditionSeverity :exec
UPDATE patient_conditions
SET 
    severity = $2,
    notes = COALESCE($3, notes),
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- FLARE-UP & CHECKUP TRACKING
-- ============================================

-- name: RecordFlareUp :exec
UPDATE patient_conditions
SET 
    last_flare_up = $2,
    status = 'active',
    notes = COALESCE($3, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateNextCheckup :exec
UPDATE patient_conditions
SET 
    next_checkup_date = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetUpcomingCheckups :many
SELECT 
    pc.id,
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    pc.condition_name,
    pc.next_checkup_date
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE 
    pc.next_checkup_date BETWEEN CURRENT_DATE AND $1
    AND pc.status IN ('active', 'managed')
ORDER BY pc.next_checkup_date ASC;

-- name: GetOverdueCheckups :many
SELECT 
    pc.id,
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    pc.condition_name,
    pc.next_checkup_date,
    pc.severity
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE 
    pc.next_checkup_date < CURRENT_DATE
    AND pc.status IN ('active', 'managed')
ORDER BY pc.next_checkup_date ASC;

-- name: GetRecentFlareUps :many
SELECT 
    pc.id,
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    pc.condition_name,
    pc.last_flare_up,
    pc.severity
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE 
    pc.last_flare_up >= $1
ORDER BY pc.last_flare_up DESC;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchConditionsByName :many
SELECT 
    id, condition_name, type, severity, status, diagnosed_date
FROM patient_conditions
WHERE 
    patient_id = $1
    AND condition_name ILIKE '%' || $2 || '%'
ORDER BY diagnosed_date DESC;

-- name: GetConditionsByICD10 :many
SELECT 
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    pc.condition_name,
    pc.severity,
    pc.status,
    pc.diagnosed_date
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE pc.icd10_code = $1
ORDER BY pc.diagnosed_date DESC;

-- name: GetPatientsByCondition :many
SELECT 
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    pc.severity,
    pc.status,
    pc.diagnosed_date,
    pp.city,
    pp.province
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE 
    pc.condition_name ILIKE '%' || $1 || '%'
    AND pc.status = 'active'
ORDER BY pc.severity DESC, pp.last_name;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientConditions :one
SELECT 
    COUNT(*) as total_conditions,
    COUNT(*) FILTER (WHERE status = 'active') as active_conditions,
    COUNT(*) FILTER (WHERE type = 'chronic') as chronic_conditions,
    COUNT(*) FILTER (WHERE severity = 'severe') as severe_conditions
FROM patient_conditions
WHERE patient_id = $1;

-- name: GetConditionStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_with_conditions,
    COUNT(*) as total_conditions,
    COUNT(*) FILTER (WHERE status = 'active') as active_conditions,
    COUNT(*) FILTER (WHERE type = 'chronic') as chronic_conditions,
    COUNT(*) FILTER (WHERE type = 'acute') as acute_conditions,
    COUNT(*) FILTER (WHERE severity = 'severe') as severe_conditions,
    AVG(EXTRACT(YEAR FROM AGE(CURRENT_DATE, diagnosed_date))) FILTER (WHERE diagnosed_date IS NOT NULL) as avg_years_since_diagnosis
FROM patient_conditions;

-- name: GetMostCommonConditions :many
SELECT 
    condition_name,
    COUNT(*) as patient_count,
    COUNT(*) FILTER (WHERE severity = 'severe') as severe_cases,
    COUNT(*) FILTER (WHERE status = 'active') as active_cases
FROM patient_conditions
GROUP BY condition_name
ORDER BY patient_count DESC
LIMIT $1;

-- name: GetConditionTypeDistribution :many
SELECT 
    type,
    COUNT(*) as condition_count,
    COUNT(DISTINCT patient_id) as patient_count,
    AVG(EXTRACT(YEAR FROM AGE(CURRENT_DATE, diagnosed_date))) FILTER (WHERE diagnosed_date IS NOT NULL) as avg_duration_years
FROM patient_conditions
WHERE status IN ('active', 'managed')
GROUP BY type
ORDER BY condition_count DESC;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetConditionsByPatientIDs :many
SELECT 
    patient_id, condition_name, type, severity, status
FROM patient_conditions
WHERE 
    patient_id = ANY($1::uuid[])
    AND status = 'active'
ORDER BY patient_id, severity DESC;

-- name: BulkUpdateConditionStatus :exec
UPDATE patient_conditions
SET 
    status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeletePatientConditions :exec
DELETE FROM patient_conditions
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: HasChronicConditions :one
SELECT EXISTS(
    SELECT 1 FROM patient_conditions
    WHERE 
        patient_id = $1
        AND type = 'chronic'
        AND status IN ('active', 'managed')
) as has_chronic;

-- name: CheckConditionExists :one
SELECT EXISTS(
    SELECT 1 FROM patient_conditions
    WHERE 
        patient_id = $1
        AND condition_name = $2
        AND status = 'active'
) as exists;

-- ============================================
-- REPORTING QUERIES
-- ============================================

-- name: GetPatientsWithMultipleConditions :many
SELECT 
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    COUNT(*) as condition_count,
    COUNT(*) FILTER (WHERE pc.type = 'chronic') as chronic_count
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE pc.status IN ('active', 'managed')
GROUP BY pc.patient_id, pp.first_name, pp.last_name
HAVING COUNT(*) >= $1
ORDER BY condition_count DESC;

-- name: GetHighRiskPatients :many
SELECT 
    pc.patient_id,
    pp.first_name,
    pp.last_name,
    COUNT(*) as severe_condition_count,
    STRING_AGG(pc.condition_name, ', ') as conditions
FROM patient_conditions pc
JOIN patient_profiles pp ON pc.patient_id = pp.id
WHERE 
    pc.severity = 'severe'
    AND pc.status = 'active'
GROUP BY pc.patient_id, pp.first_name, pp.last_name
ORDER BY severe_condition_count DESC;

-- name: GetEmergencyConditionInfo :many
SELECT 
    condition_name,
    type,
    severity,
    last_flare_up,
    notes
FROM patient_conditions
WHERE 
    patient_id = $1
    AND status IN ('active', 'managed')
ORDER BY severity DESC;
