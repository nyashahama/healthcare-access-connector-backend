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

-- name: GetPatientAllergiesByStatus :many
SELECT 
    id, allergy_name, severity, reaction_description,
    first_identified_date, status
FROM patient_allergies
WHERE 
    patient_id = $1
    AND status = $2
ORDER BY severity DESC, first_identified_date DESC;

-- ============================================
-- SEVERITY-BASED QUERIES
-- ============================================

-- name: GetSevereAllergies :many
SELECT 
    id, allergy_name, severity, reaction_description,
    last_occurrence_date
FROM patient_allergies
WHERE 
    patient_id = $1
    AND severity IN ('severe', 'life_threatening')
    AND status = 'active'
ORDER BY 
    CASE severity
        WHEN 'life_threatening' THEN 1
        WHEN 'severe' THEN 2
        ELSE 3
    END;

-- name: GetLifeThreateningAllergies :many
SELECT 
    id, allergy_name, reaction_description,
    first_identified_date, last_occurrence_date
FROM patient_allergies
WHERE 
    patient_id = $1
    AND severity = 'life_threatening'
    AND status = 'active'
ORDER BY first_identified_date DESC;

-- name: GetPatientsBySeverity :many
SELECT 
    pa.patient_id,
    pp.first_name,
    pp.last_name,
    pa.allergy_name,
    pa.severity,
    pa.reaction_description
FROM patient_allergies pa
JOIN patient_profiles pp ON pa.patient_id = pp.id
WHERE 
    pa.severity = $1
    AND pa.status = 'active'
ORDER BY pp.last_name, pp.first_name;

-- ============================================
-- STATUS MANAGEMENT
-- ============================================

-- name: UpdateAllergyStatus :exec
UPDATE patient_allergies
SET 
    status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: MarkAllergyResolved :exec
UPDATE patient_allergies
SET 
    status = 'resolved',
    notes = COALESCE($2, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: MarkAllergyInactive :exec
UPDATE patient_allergies
SET 
    status = 'inactive',
    notes = COALESCE($2, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: ReactivateAllergy :exec
UPDATE patient_allergies
SET 
    status = 'active',
    last_occurrence_date = CURRENT_DATE,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- OCCURRENCE TRACKING
-- ============================================

-- name: RecordAllergyOccurrence :exec
UPDATE patient_allergies
SET 
    last_occurrence_date = $2,
    reaction_description = COALESCE($3, reaction_description),
    status = 'active',
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateLastOccurrence :exec
UPDATE patient_allergies
SET 
    last_occurrence_date = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetRecentAllergyOccurrences :many
SELECT 
    pa.id,
    pa.patient_id,
    pp.first_name,
    pp.last_name,
    pa.allergy_name,
    pa.severity,
    pa.last_occurrence_date,
    pa.reaction_description
FROM patient_allergies pa
JOIN patient_profiles pp ON pa.patient_id = pp.id
WHERE 
    pa.last_occurrence_date >= $1
    AND pa.status = 'active'
ORDER BY pa.last_occurrence_date DESC;

-- ============================================
-- ALLERGY TYPE QUERIES
-- ============================================

-- name: GetPatientsByAllergyName :many
SELECT 
    pa.patient_id,
    pp.first_name,
    pp.last_name,
    pa.severity,
    pa.reaction_description,
    pp.city,
    pp.province
FROM patient_allergies pa
JOIN patient_profiles pp ON pa.patient_id = pp.id
WHERE 
    pa.allergy_name ILIKE '%' || $1 || '%'
    AND pa.status = 'active'
ORDER BY 
    CASE pa.severity
        WHEN 'life_threatening' THEN 1
        WHEN 'severe' THEN 2
        WHEN 'moderate' THEN 3
        WHEN 'mild' THEN 4
        ELSE 5
    END,
    pp.last_name;

-- name: SearchAllergiesByName :many
SELECT 
    id, patient_id, allergy_name, severity,
    reaction_description, status
FROM patient_allergies
WHERE 
    patient_id = $1
    AND allergy_name ILIKE '%' || $2 || '%'
ORDER BY severity DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientAllergies :one
SELECT 
    COUNT(*) as total_allergies,
    COUNT(*) FILTER (WHERE status = 'active') as active_allergies,
    COUNT(*) FILTER (WHERE severity = 'life_threatening') as life_threatening,
    COUNT(*) FILTER (WHERE severity = 'severe') as severe,
    COUNT(*) FILTER (WHERE severity = 'moderate') as moderate,
    COUNT(*) FILTER (WHERE severity = 'mild') as mild
FROM patient_allergies
WHERE patient_id = $1;

-- name: GetAllergySeverityDistribution :many
SELECT 
    severity,
    COUNT(*) as allergy_count,
    COUNT(DISTINCT patient_id) as patient_count
FROM patient_allergies
WHERE status = 'active'
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'life_threatening' THEN 1
        WHEN 'severe' THEN 2
        WHEN 'moderate' THEN 3
        WHEN 'mild' THEN 4
        ELSE 5
    END;

-- name: GetMostCommonAllergies :many
SELECT 
    allergy_name,
    COUNT(*) as patient_count,
    COUNT(*) FILTER (WHERE severity IN ('severe', 'life_threatening')) as severe_cases
FROM patient_allergies
WHERE status = 'active'
GROUP BY allergy_name
ORDER BY patient_count DESC
LIMIT $1;

-- name: GetAllergyStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as total_patients_with_allergies,
    COUNT(*) as total_allergies,
    COUNT(*) FILTER (WHERE status = 'active') as active_allergies,
    COUNT(*) FILTER (WHERE severity = 'life_threatening') as life_threatening_count,
    COUNT(*) FILTER (WHERE severity = 'severe') as severe_count,
    AVG(EXTRACT(YEAR FROM AGE(CURRENT_DATE, first_identified_date))) FILTER (WHERE first_identified_date IS NOT NULL) as avg_years_since_identification
FROM patient_allergies;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetAllergiesByPatientIDs :many
SELECT 
    patient_id, allergy_name, severity, status
FROM patient_allergies
WHERE 
    patient_id = ANY($1::uuid[])
    AND status = 'active'
ORDER BY 
    patient_id,
    CASE severity
        WHEN 'life_threatening' THEN 1
        WHEN 'severe' THEN 2
        WHEN 'moderate' THEN 3
        WHEN 'mild' THEN 4
        ELSE 5
    END;

-- name: BulkUpdateAllergyStatus :exec
UPDATE patient_allergies
SET 
    status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeletePatientAllergies :exec
DELETE FROM patient_allergies
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: CheckAllergyExists :one
SELECT EXISTS(
    SELECT 1 FROM patient_allergies
    WHERE 
        patient_id = $1
        AND allergy_name = $2
        AND status = 'active'
) as exists;

-- name: HasLifeThreateningAllergies :one
SELECT EXISTS(
    SELECT 1 FROM patient_allergies
    WHERE 
        patient_id = $1
        AND severity = 'life_threatening'
        AND status = 'active'
) as has_life_threatening;

-- name: GetPatientAllergyCount :one
SELECT COUNT(*) as allergy_count
FROM patient_allergies
WHERE 
    patient_id = $1
    AND status = 'active';

-- ============================================
-- REPORTING QUERIES
-- ============================================

-- name: GetPatientsWithMultipleAllergies :many
SELECT 
    pa.patient_id,
    pp.first_name,
    pp.last_name,
    COUNT(*) as allergy_count,
    COUNT(*) FILTER (WHERE pa.severity IN ('severe', 'life_threatening')) as severe_count
FROM patient_allergies pa
JOIN patient_profiles pp ON pa.patient_id = pp.id
WHERE pa.status = 'active'
GROUP BY pa.patient_id, pp.first_name, pp.last_name
HAVING COUNT(*) >= $1
ORDER BY allergy_count DESC, pp.last_name;

-- name: GetPatientsWithNoAllergies :many
SELECT 
    pp.id as patient_id,
    pp.user_id,
    pp.first_name,
    pp.last_name,
    pp.city,
    pp.province
FROM patient_profiles pp
LEFT JOIN patient_allergies pa ON pp.id = pa.patient_id AND pa.status = 'active'
WHERE pa.id IS NULL
ORDER BY pp.last_name, pp.first_name
LIMIT $1 OFFSET $2;

-- name: GetUnresolvedAllergies :many
SELECT 
    pa.patient_id,
    pp.first_name,
    pp.last_name,
    pa.allergy_name,
    pa.severity,
    pa.first_identified_date,
    EXTRACT(YEAR FROM AGE(CURRENT_DATE, pa.first_identified_date))::INTEGER as years_active
FROM patient_allergies pa
JOIN patient_profiles pp ON pa.patient_id = pp.id
WHERE 
    pa.status = 'active'
    AND pa.first_identified_date < CURRENT_DATE - INTERVAL '5 years'
ORDER BY pa.first_identified_date ASC;

-- name: GetAllergiesByDateRange :many
SELECT 
    pa.id,
    pa.patient_id,
    pp.first_name,
    pp.last_name,
    pa.allergy_name,
    pa.severity,
    pa.first_identified_date
FROM patient_allergies pa
JOIN patient_profiles pp ON pa.patient_id = pp.id
WHERE 
    pa.first_identified_date BETWEEN $1 AND $2
ORDER BY pa.first_identified_date DESC;

-- ============================================
-- EMERGENCY ACCESS QUERIES
-- ============================================

-- name: GetEmergencyAllergyInfo :many
SELECT 
    allergy_name,
    severity,
    reaction_description
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

-- name: GetCriticalAllergyWarnings :one
SELECT 
    COUNT(*) FILTER (WHERE severity = 'life_threatening') as life_threatening_count,
    COUNT(*) FILTER (WHERE severity = 'severe') as severe_count,
    STRING_AGG(
        CASE WHEN severity IN ('life_threatening', 'severe') 
        THEN allergy_name 
        ELSE NULL END, 
        ', '
    ) as critical_allergies
FROM patient_allergies
WHERE 
    patient_id = $1
    AND status = 'active';
