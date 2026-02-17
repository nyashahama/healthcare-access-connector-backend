-- ============================================
-- CORE WRITE OPERATIONS
-- ============================================

-- name: CreateConsultationNote :one
-- Provider opens the notes panel → create draft immediately.
INSERT INTO consultation_notes (
    consultation_id, authored_by_staff_id
)
VALUES ($1, $2)
RETURNING *;

-- name: UpdateConsultationNote :one
-- Auto-save as provider types. Blocked once is_finalised = true (enforced at service layer).
UPDATE consultation_notes
SET
    subjective           = COALESCE($2, subjective),
    objective            = COALESCE($3, objective),
    assessment           = COALESCE($4, assessment),
    plan                 = COALESCE($5, plan),
    diagnosis_codes      = COALESCE($6, diagnosis_codes),
    prescription_issued  = COALESCE($7, prescription_issued),
    prescription_details = COALESCE($8::jsonb, prescription_details),
    referral_required    = COALESCE($9, referral_required),
    referral_type        = COALESCE($10, referral_type),
    referral_notes       = COALESCE($11, referral_notes),
    follow_up_recommended = COALESCE($12, follow_up_recommended),
    follow_up_timeframe  = COALESCE($13, follow_up_timeframe),
    updated_at           = NOW()
WHERE id = $1
  AND is_finalised = false
RETURNING *;

-- name: FinaliseConsultationNote :one
-- Locks the note. Called when provider clicks "End Consultation".
UPDATE consultation_notes
SET
    is_finalised = true,
    finalised_at = NOW(),
    updated_at   = NOW()
WHERE id = $1
  AND is_finalised = false
RETURNING *;

-- name: FinaliseNoteByConsultation :one
-- Alternative: lock by consultation_id (more natural from the service layer).
UPDATE consultation_notes
SET
    is_finalised = true,
    finalised_at = NOW(),
    updated_at   = NOW()
WHERE consultation_id = $1
  AND is_finalised = false
RETURNING *;


-- ============================================
-- READ OPERATIONS
-- ============================================

-- name: GetNoteByID :one
SELECT * FROM consultation_notes
WHERE id = $1;

-- name: GetNoteByConsultationID :one
-- Primary read path — get the note for a given consultation.
SELECT * FROM consultation_notes
WHERE consultation_id = $1;

-- name: GetNoteWithProviderInfo :one
-- Hydrated view for patient record / admin audit.
SELECT
    cn.*,
    cs.first_name       AS provider_first_name,
    cs.last_name        AS provider_last_name,
    cs.professional_title,
    cs.specialization,
    cs.hpcs_number
FROM consultation_notes cn
JOIN clinic_staff cs ON cs.id = cn.authored_by_staff_id
WHERE cn.consultation_id = $1;


-- ============================================
-- PROVIDER HISTORY
-- ============================================

-- name: GetProviderNoteHistory :many
-- All finalised notes written by a provider, newest first.
SELECT
    cn.id,
    cn.consultation_id,
    cn.assessment,
    cn.plan,
    cn.diagnosis_codes,
    cn.prescription_issued,
    cn.referral_required,
    cn.follow_up_recommended,
    cn.finalised_at,
    pp.first_name AS patient_first_name,
    pp.last_name  AS patient_last_name
FROM consultation_notes cn
JOIN consultations    c  ON c.id  = cn.consultation_id
JOIN patient_profiles pp ON pp.id = c.patient_id
WHERE
    cn.authored_by_staff_id = $1
    AND cn.is_finalised     = true
ORDER BY cn.finalised_at DESC
LIMIT  $2
OFFSET $3;


-- ============================================
-- PATIENT RECORD ACCESS
-- ============================================

-- name: GetPatientNoteHistory :many
-- All finalised notes for a patient (their full telemedicine record).
SELECT
    cn.id,
    cn.consultation_id,
    cn.subjective,
    cn.assessment,
    cn.plan,
    cn.diagnosis_codes,
    cn.prescription_issued,
    cn.prescription_details,
    cn.referral_required,
    cn.referral_type,
    cn.follow_up_recommended,
    cn.follow_up_timeframe,
    cn.finalised_at,
    cs.first_name       AS provider_first_name,
    cs.last_name        AS provider_last_name,
    cs.professional_title
FROM consultation_notes cn
JOIN consultations    c  ON c.id  = cn.consultation_id
JOIN clinic_staff    cs  ON cs.id = cn.authored_by_staff_id
WHERE
    c.patient_id    = $1
    AND cn.is_finalised = true
ORDER BY cn.finalised_at DESC;


-- ============================================
-- QUICK CHECKS
-- ============================================

-- name: NoteExistsForConsultation :one
SELECT EXISTS(
    SELECT 1 FROM consultation_notes
    WHERE consultation_id = $1
) AS exists;

-- name: IsNoteFinalisedForConsultation :one
SELECT is_finalised FROM consultation_notes
WHERE consultation_id = $1;
