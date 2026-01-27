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

-- name: GetDependentsByRelationship :many
SELECT 
    id, first_name, last_name, date_of_birth, gender, health_status
FROM patient_dependents
WHERE 
    patient_id = $1
    AND relationship = $2
ORDER BY date_of_birth DESC;

-- ============================================
-- HEALTH & DEVELOPMENT TRACKING
-- ============================================

-- name: UpdateDependentHealth :exec
UPDATE patient_dependents
SET 
    health_status = $2,
    primary_pediatrician = COALESCE($3, primary_pediatrician),
    clinic_id = COALESCE($4, clinic_id),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateBirthMetrics :exec
UPDATE patient_dependents
SET 
    birth_weight_kg = $2,
    birth_height_cm = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetDependentsByHealthStatus :many
SELECT 
    pd.id,
    pd.patient_id,
    pp.first_name as parent_first_name,
    pp.last_name as parent_last_name,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth,
    pd.health_status
FROM patient_dependents pd
JOIN patient_profiles pp ON pd.patient_id = pp.id
WHERE pd.health_status = $1
ORDER BY pd.date_of_birth DESC;

-- ============================================
-- SPECIAL NEEDS MANAGEMENT
-- ============================================

-- name: GetDependentsWithSpecialNeeds :many
SELECT 
    pd.id,
    pd.patient_id,
    pp.first_name as parent_first_name,
    pp.last_name as parent_last_name,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth,
    pd.special_needs_description,
    pp.city,
    pp.province
FROM patient_dependents pd
JOIN patient_profiles pp ON pd.patient_id = pp.id
WHERE pd.has_special_needs = true
ORDER BY pd.date_of_birth DESC;

-- name: UpdateSpecialNeeds :exec
UPDATE patient_dependents
SET 
    has_special_needs = $2,
    special_needs_description = $3,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- GUARDIANSHIP & LEGAL
-- ============================================

-- name: UpdateGuardianship :exec
UPDATE patient_dependents
SET 
    has_legal_guardianship = $2,
    guardianship_document_url = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetDependentsWithoutGuardianship :many
SELECT 
    pd.id,
    pd.patient_id,
    pp.first_name as parent_first_name,
    pp.last_name as parent_last_name,
    pd.first_name,
    pd.last_name,
    pd.relationship,
    pp.city,
    pp.province
FROM patient_dependents pd
JOIN patient_profiles pp ON pd.patient_id = pp.id
WHERE pd.has_legal_guardianship = false
ORDER BY pd.created_at DESC;

-- ============================================
-- EDUCATION & SCHOOL
-- ============================================

-- name: UpdateSchoolInfo :exec
UPDATE patient_dependents
SET 
    school_name = $2,
    grade = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetDependentsBySchool :many
SELECT 
    id, patient_id, first_name, last_name,
    date_of_birth, grade
FROM patient_dependents
WHERE school_name = $1
ORDER BY grade, last_name, first_name;

-- name: GetSchoolAgeChildren :many
SELECT 
    pd.id,
    pd.patient_id,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth,
    EXTRACT(YEAR FROM AGE(pd.date_of_birth))::INTEGER as age,
    pd.school_name,
    pd.grade
FROM patient_dependents pd
WHERE 
    pd.patient_id = $1
    AND EXTRACT(YEAR FROM AGE(pd.date_of_birth)) BETWEEN 5 AND 18
ORDER BY pd.date_of_birth DESC;

-- ============================================
-- HEALTHCARE PROVIDER TRACKING
-- ============================================

-- name: UpdatePediatrician :exec
UPDATE patient_dependents
SET 
    primary_pediatrician = $2,
    clinic_id = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetDependentsByPediatrician :many
SELECT 
    pd.id,
    pd.patient_id,
    pp.first_name as parent_first_name,
    pp.last_name as parent_last_name,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth
FROM patient_dependents pd
JOIN patient_profiles pp ON pd.patient_id = pp.id
WHERE pd.primary_pediatrician = $1
ORDER BY pd.date_of_birth DESC;

-- name: GetDependentsByClinic :many
SELECT 
    pd.id,
    pd.patient_id,
    pp.first_name as parent_first_name,
    pp.last_name as parent_last_name,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth,
    pd.primary_pediatrician
FROM patient_dependents pd
JOIN patient_profiles pp ON pd.patient_id = pp.id
WHERE pd.clinic_id = $1
ORDER BY pd.date_of_birth DESC;

-- ============================================
-- AGE & DEMOGRAPHIC QUERIES
-- ============================================

-- name: GetDependentsByAgeRange :many
SELECT 
    id, patient_id, first_name, last_name,
    date_of_birth,
    EXTRACT(YEAR FROM AGE(date_of_birth))::INTEGER as age,
    health_status
FROM patient_dependents
WHERE 
    patient_id = $1
    AND EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN $2 AND $3
ORDER BY date_of_birth DESC;

-- name: GetInfants :many
SELECT 
    pd.id,
    pd.patient_id,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth,
    EXTRACT(MONTH FROM AGE(pd.date_of_birth))::INTEGER as age_months,
    pd.health_status
FROM patient_dependents pd
WHERE 
    pd.date_of_birth >= CURRENT_DATE - INTERVAL '2 years'
ORDER BY pd.date_of_birth DESC;

-- name: GetToddlers :many
SELECT 
    pd.id,
    pd.patient_id,
    pd.first_name,
    pd.last_name,
    pd.date_of_birth,
    EXTRACT(YEAR FROM AGE(pd.date_of_birth))::INTEGER as age,
    pd.health_status
FROM patient_dependents pd
WHERE 
    EXTRACT(YEAR FROM AGE(pd.date_of_birth)) BETWEEN 1 AND 3
ORDER BY pd.date_of_birth DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientDependents :one
SELECT 
    COUNT(*) as total_dependents,
    COUNT(*) FILTER (WHERE relationship = 'child') as children_count,
    COUNT(*) FILTER (WHERE has_special_needs = true) as special_needs_count,
    COUNT(*) FILTER (WHERE has_legal_guardianship = false) as without_guardianship,
    AVG(EXTRACT(YEAR FROM AGE(date_of_birth))) as average_age
FROM patient_dependents
WHERE patient_id = $1;

-- name: GetDependentStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_with_dependents,
    COUNT(*) as total_dependents,
    COUNT(*) FILTER (WHERE relationship = 'child') as children,
    COUNT(*) FILTER (WHERE has_special_needs = true) as with_special_needs,
    AVG(EXTRACT(YEAR FROM AGE(date_of_birth))) as avg_age,
    COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(date_of_birth)) < 5) as under_5,
    COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 5 AND 12) as age_5_to_12,
    COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 13 AND 18) as age_13_to_18
FROM patient_dependents;

-- name: GetDependentAgeDistribution :many
SELECT 
    CASE
        WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) < 2 THEN 'Infant (0-1)'
        WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 2 AND 4 THEN 'Toddler (2-4)'
        WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 5 AND 12 THEN 'Child (5-12)'
        WHEN EXTRACT(YEAR FROM AGE(date_of_birth)) BETWEEN 13 AND 18 THEN 'Teen (13-18)'
        ELSE 'Adult'
    END as age_group,
    COUNT(*) as dependent_count
FROM patient_dependents
GROUP BY age_group
ORDER BY 
    CASE age_group
        WHEN 'Infant (0-1)' THEN 1
        WHEN 'Toddler (2-4)' THEN 2
        WHEN 'Child (5-12)' THEN 3
        WHEN 'Teen (13-18)' THEN 4
        ELSE 5
    END;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetDependentsByPatientIDs :many
SELECT 
    patient_id, first_name, last_name, date_of_birth, relationship
FROM patient_dependents
WHERE patient_id = ANY($1::uuid[])
ORDER BY patient_id, date_of_birth DESC;

-- name: DeletePatientDependents :exec
DELETE FROM patient_dependents
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: HasDependents :one
SELECT EXISTS(
    SELECT 1 FROM patient_dependents
    WHERE patient_id = $1
) as has_dependents;

-- name: GetDependentAge :one
SELECT EXTRACT(YEAR FROM AGE(date_of_birth))::INTEGER as age
FROM patient_dependents
WHERE id = $1;

-- name: GetDependentFullName :one
SELECT first_name || ' ' || last_name as full_name
FROM patient_dependents
WHERE id = $1;