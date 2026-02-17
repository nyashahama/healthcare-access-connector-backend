-- ============================================
-- CONSULTATIONS REPOSITORY QUERIES
-- Maps to: ConsultationRepository interface
-- Domain: Telemedicine / Provider-Patient Sessions
-- ============================================

-- ============================================
-- SCHEMA
-- ============================================

CREATE TABLE consultations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Required gate: must come from a completed symptom session
    symptom_session_id   UUID NOT NULL REFERENCES symptom_checker_sessions(id) ON DELETE RESTRICT,
    patient_id           UUID NOT NULL REFERENCES patient_profiles(id) ON DELETE CASCADE,
    provider_staff_id    UUID REFERENCES clinic_staff(id) ON DELETE SET NULL,
    clinic_id            UUID REFERENCES clinics(id) ON DELETE SET NULL,

    -- Channel: 'chat' now, extensible to 'video' | 'phone' later
    channel              VARCHAR(20) NOT NULL DEFAULT 'chat',

    -- Lifecycle timestamps
    requested_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at          TIMESTAMP,
    started_at           TIMESTAMP,
    ended_at             TIMESTAMP,
    duration_seconds     INTEGER,

    -- Status
    status               VARCHAR(30) NOT NULL DEFAULT 'pending_acceptance',
        -- 'pending_acceptance' | 'accepted' | 'in_progress'
        -- | 'completed' | 'cancelled' | 'no_show' | 'escalated' | 'declined'
    triage_level_at_start VARCHAR(20),   -- copied from session at creation
    ended_by             UUID REFERENCES users(id) ON DELETE SET NULL,
    end_reason           VARCHAR(50),
        -- 'completed' | 'no_show' | 'cancelled' | 'escalated'

    -- Billing
    consultation_fee     DECIMAL(10,2),
    fee_currency         VARCHAR(3) NOT NULL DEFAULT 'ZAR',
    payment_status       VARCHAR(20) NOT NULL DEFAULT 'pending',
        -- 'pending' | 'paid' | 'waived' | 'failed'
    payment_reference    VARCHAR(100),

    -- Post-consultation rating (from patient)
    patient_rating       INTEGER CHECK (patient_rating BETWEEN 1 AND 5),
    patient_feedback     TEXT,
    rated_at             TIMESTAMP,

    -- Optional: follow-up appointment booked in the same flow
    follow_up_appointment_id UUID REFERENCES appointments(id) ON DELETE SET NULL,

    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_consultation_status CHECK (status IN (
        'pending_acceptance', 'accepted', 'in_progress',
        'completed', 'cancelled', 'no_show', 'escalated', 'declined'
    )),
    CONSTRAINT valid_channel CHECK (channel IN ('chat', 'video', 'phone')),
    CONSTRAINT valid_payment_status CHECK (payment_status IN ('pending', 'paid', 'waived', 'failed'))
);

CREATE INDEX idx_consultations_patient         ON consultations(patient_id);
CREATE INDEX idx_consultations_provider        ON consultations(provider_staff_id);
CREATE INDEX idx_consultations_status          ON consultations(status);
CREATE INDEX idx_consultations_triage          ON consultations(triage_level_at_start);
CREATE INDEX idx_consultations_requested_at    ON consultations(requested_at DESC);
CREATE INDEX idx_consultations_symptom_session ON consultations(symptom_session_id);
-- Partial index: fast lookup of open consultations per provider
CREATE INDEX idx_consultations_provider_open   ON consultations(provider_staff_id, status)
    WHERE status IN ('accepted', 'in_progress', 'pending_acceptance');


-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateConsultation :one
INSERT INTO consultations (
    symptom_session_id, patient_id, triage_level_at_start,
    channel, consultation_fee, fee_currency
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetConsultationByID :one
SELECT * FROM consultations
WHERE id = $1;

-- name: GetConsultationWithDetails :one
-- Full consultation row joined with session summary and patient name.
-- Used by both patient and provider to hydrate a chat screen.
SELECT
    c.*,
    scs.chief_complaint,
    scs.ai_summary,
    scs.triage_level             AS session_triage_level,
    scs.symptoms_reported,
    pp.first_name                AS patient_first_name,
    pp.last_name                 AS patient_last_name,
    pp.preferred_communication_method,
    cs.first_name                AS provider_first_name,
    cs.last_name                 AS provider_last_name,
    cs.specialization            AS provider_specialization,
    cs.professional_title        AS provider_title
FROM consultations c
JOIN symptom_checker_sessions scs ON scs.id = c.symptom_session_id
JOIN patient_profiles         pp  ON pp.id  = c.patient_id
LEFT JOIN clinic_staff         cs  ON cs.id  = c.provider_staff_id
WHERE c.id = $1;


-- ============================================
-- STATUS TRANSITIONS
-- ============================================

-- name: AcceptConsultation :one
-- Provider accepts from waiting room.
UPDATE consultations
SET
    provider_staff_id = $2,
    clinic_id         = $3,
    status            = 'accepted',
    accepted_at       = NOW(),
    updated_at        = NOW()
WHERE id = $1
  AND status = 'pending_acceptance'
RETURNING *;

-- name: StartConsultation :one
-- First message sent — move from accepted → in_progress.
UPDATE consultations
SET
    status     = 'in_progress',
    started_at = NOW(),
    updated_at = NOW()
WHERE id = $1
  AND status = 'accepted'
RETURNING *;

-- name: CompleteConsultation :one
UPDATE consultations
SET
    status           = 'completed',
    ended_at         = NOW(),
    duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::INTEGER,
    ended_by         = $2,
    end_reason       = 'completed',
    updated_at       = NOW()
WHERE id = $1
  AND status = 'in_progress'
RETURNING *;

-- name: CancelConsultation :one
UPDATE consultations
SET
    status     = 'cancelled',
    ended_at   = NOW(),
    ended_by   = $2,
    end_reason = 'cancelled',
    updated_at = NOW()
WHERE id = $1
  AND status IN ('pending_acceptance', 'accepted')
RETURNING *;

-- name: DeclineConsultation :exec
-- Provider declines — patient will see a new provider list.
UPDATE consultations
SET
    status     = 'declined',
    ended_at   = NOW(),
    end_reason = 'declined',
    updated_at = NOW()
WHERE id = $1
  AND status = 'pending_acceptance';

-- name: EscalateConsultation :one
UPDATE consultations
SET
    status     = 'escalated',
    ended_at   = NOW(),
    ended_by   = $2,
    end_reason = 'escalated',
    updated_at = NOW()
WHERE id = $1
  AND status = 'in_progress'
RETURNING *;

-- name: MarkNoShow :exec
UPDATE consultations
SET
    status     = 'no_show',
    ended_at   = NOW(),
    end_reason = 'no_show',
    updated_at = NOW()
WHERE id = $1
  AND status = 'accepted';

-- name: UpdateConsultationChannel :exec
-- Used when upgrading chat → video.
UPDATE consultations
SET
    channel    = $2,
    updated_at = NOW()
WHERE id = $1;


-- ============================================
-- BILLING
-- ============================================

-- name: UpdatePaymentStatus :exec
UPDATE consultations
SET
    payment_status    = $2,
    payment_reference = $3,
    updated_at        = NOW()
WHERE id = $1;

-- name: SetConsultationFee :exec
UPDATE consultations
SET
    consultation_fee = $2,
    updated_at       = NOW()
WHERE id = $1;


-- ============================================
-- RATING
-- ============================================

-- name: SubmitPatientRating :exec
-- Called from RatingModal after chat ends.
UPDATE consultations
SET
    patient_rating   = $2,
    patient_feedback = $3,
    rated_at         = NOW(),
    updated_at       = NOW()
WHERE id = $1
  AND status IN ('completed', 'escalated')
  AND patient_rating IS NULL;

-- name: LinkFollowUpAppointment :exec
UPDATE consultations
SET
    follow_up_appointment_id = $2,
    updated_at               = NOW()
WHERE id = $1;


-- ============================================
-- PATIENT-FACING QUERIES
-- ============================================

-- name: GetPatientConsultations :many
-- Full consultation history for a patient.
SELECT
    c.id, c.status, c.channel, c.triage_level_at_start,
    c.requested_at, c.started_at, c.ended_at, c.duration_seconds,
    c.consultation_fee, c.payment_status,
    c.patient_rating,
    scs.chief_complaint,
    cs.first_name    AS provider_first_name,
    cs.last_name     AS provider_last_name,
    cs.specialization AS provider_specialization
FROM consultations c
JOIN symptom_checker_sessions scs ON scs.id = c.symptom_session_id
LEFT JOIN clinic_staff         cs  ON cs.id  = c.provider_staff_id
WHERE c.patient_id = $1
ORDER BY c.requested_at DESC
LIMIT  $2
OFFSET $3;

-- name: GetPatientActiveConsultation :one
-- Check if the patient already has an open consultation (prevent duplicates).
SELECT id, status, provider_staff_id, channel
FROM consultations
WHERE
    patient_id = $1
    AND status IN ('pending_acceptance', 'accepted', 'in_progress')
LIMIT 1;


-- ============================================
-- PROVIDER-FACING QUERIES
-- ============================================

-- name: GetProviderActiveConsultations :many
-- Provider dashboard: all open consultations with unread counts and triage priority.
SELECT
    c.id,
    c.status,
    c.triage_level_at_start,
    c.requested_at,
    c.started_at,
    c.channel,

    -- Patient identity
    pp.first_name              AS patient_first_name,
    pp.last_name               AS patient_last_name,
    pp.preferred_communication_method,
    pp.requires_interpreter,

    -- Symptom context
    scs.chief_complaint,
    scs.ai_summary,
    scs.severity_score,

    -- Unread message count
    COUNT(cm.id) FILTER (
        WHERE cm.sender_role = 'patient' AND cm.is_read = false
    )                          AS unread_messages
FROM consultations c
JOIN patient_profiles         pp  ON pp.id  = c.patient_id
JOIN symptom_checker_sessions scs ON scs.id = c.symptom_session_id
LEFT JOIN consultation_messages cm ON cm.consultation_id = c.id
WHERE
    c.provider_staff_id = $1
    AND c.status IN ('accepted', 'in_progress', 'pending_acceptance')
GROUP BY c.id, pp.id, scs.id
ORDER BY
    CASE c.triage_level_at_start
        WHEN 'emergency' THEN 1
        WHEN 'high'      THEN 2
        WHEN 'medium'    THEN 3
        ELSE 4
    END,
    c.requested_at ASC;

-- name: GetWaitingRoom :many
-- All pending_acceptance consultations — shown to providers scanning for new patients.
SELECT
    c.id,
    c.triage_level_at_start,
    c.requested_at,
    c.channel,
    c.consultation_fee,
    pp.first_name      AS patient_first_name,
    pp.last_name       AS patient_last_name,
    scs.chief_complaint,
    scs.severity_score,
    scs.ai_summary
FROM consultations c
JOIN patient_profiles         pp  ON pp.id  = c.patient_id
JOIN symptom_checker_sessions scs ON scs.id = c.symptom_session_id
WHERE c.status = 'pending_acceptance'
ORDER BY
    CASE c.triage_level_at_start
        WHEN 'emergency' THEN 1
        WHEN 'high'      THEN 2
        WHEN 'medium'    THEN 3
        ELSE 4
    END,
    c.requested_at ASC;

-- name: GetProviderConsultationHistory :many
SELECT
    c.id, c.status, c.channel,
    c.requested_at, c.ended_at, c.duration_seconds,
    c.consultation_fee, c.payment_status,
    c.patient_rating, c.end_reason,
    pp.first_name AS patient_first_name,
    pp.last_name  AS patient_last_name,
    scs.chief_complaint
FROM consultations c
JOIN patient_profiles         pp  ON pp.id  = c.patient_id
JOIN symptom_checker_sessions scs ON scs.id = c.symptom_session_id
WHERE
    c.provider_staff_id = $1
    AND c.status IN ('completed', 'no_show', 'escalated', 'cancelled')
ORDER BY c.ended_at DESC
LIMIT  $2
OFFSET $3;
