-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateSymptomSession :one
INSERT INTO symptom_checker_sessions (
    patient_id, user_id, dependent_id,
    chief_complaint, symptom_duration, symptoms_reported,
    body_systems_affected, severity_score, triage_level,
    is_for_dependent, ai_summary, recommended_action,
    status, raw_answers
)
VALUES (
    $1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13, $14::jsonb
)
RETURNING *;

-- name: GetSymptomSessionByID :one
SELECT * FROM symptom_checker_sessions
WHERE id = $1;

-- name: UpdateSessionStatus :exec
UPDATE symptom_checker_sessions
SET
    status     = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: MarkSessionConverted :exec
-- Called when a consultation is created from this session
UPDATE symptom_checker_sessions
SET
    status     = 'converted_to_consult',
    updated_at = NOW()
WHERE id = $1
  AND status = 'completed';


-- ============================================
-- PATIENT-FACING QUERIES
-- ============================================

-- name: GetLatestEligibleSession :one
-- Preflight check: patient has a recent telemedicine-eligible session.
-- Called before showing the provider list.
SELECT
    id, triage_level, ai_summary, recommended_action,
    chief_complaint, symptoms_reported, body_systems_affected,
    severity_score, is_for_dependent, dependent_id, created_at
FROM symptom_checker_sessions
WHERE
    patient_id        = $1
    AND status        = 'completed'
    AND recommended_action = 'telemedicine'
    AND created_at    > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC
LIMIT 1;

-- name: GetPatientSessions :many
-- Patient session history, newest first.
SELECT
    id, chief_complaint, triage_level, recommended_action,
    severity_score, status, is_for_dependent, dependent_id, created_at
FROM symptom_checker_sessions
WHERE patient_id = $1
ORDER BY created_at DESC
LIMIT  $2
OFFSET $3;

-- name: GetDependentSessions :many
-- All sessions filed on behalf of a specific dependent.
SELECT
    id, chief_complaint, triage_level, recommended_action,
    severity_score, status, created_at
FROM symptom_checker_sessions
WHERE
    patient_id   = $1
    AND dependent_id = $2
ORDER BY created_at DESC;


-- ============================================
-- PROVIDER-FACING QUERIES
-- ============================================

-- name: GetSessionWithPatientContext :one
-- Joins symptom session with patient profile + medical info.
-- Used to populate the provider's context panel on consultation accept.
SELECT
    scs.id                      AS session_id,
    scs.chief_complaint,
    scs.symptom_duration,
    scs.symptoms_reported,
    scs.body_systems_affected,
    scs.severity_score,
    scs.triage_level,
    scs.ai_summary,
    scs.recommended_action,
    scs.is_for_dependent,
    scs.dependent_id,

    -- Patient demographics
    pp.id                       AS patient_id,
    pp.first_name,
    pp.last_name,
    pp.date_of_birth,
    pp.gender,
    pp.preferred_communication_method,
    pp.language_preferences,
    pp.requires_interpreter,

    -- Medical summary
    pmi.blood_type,
    pmi.overall_health_status,
    pmi.health_summary
FROM symptom_checker_sessions scs
JOIN patient_profiles         pp  ON pp.id  = scs.patient_id
LEFT JOIN patient_medical_info pmi ON pmi.patient_id = scs.patient_id
WHERE scs.id = $1;


-- ============================================
-- ADMIN / ANALYTICS
-- ============================================

-- name: GetSessionsByTriageLevel :many
SELECT
    id, patient_id, triage_level, recommended_action,
    severity_score, status, created_at
FROM symptom_checker_sessions
WHERE
    triage_level = $1
    AND created_at BETWEEN $2 AND $3
ORDER BY created_at DESC
LIMIT  $4
OFFSET $5;

-- name: CountSessionsByOutcome :one
-- Quick analytics: how many sessions per recommended_action in a window.
SELECT
    recommended_action,
    COUNT(*) AS total
FROM symptom_checker_sessions
WHERE created_at BETWEEN $1 AND $2
GROUP BY recommended_action;
