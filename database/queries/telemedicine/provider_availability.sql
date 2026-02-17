-- ============================================
-- UPSERT / INITIALISE
-- ============================================

-- name: UpsertProviderAvailability :one
-- Creates a row on first login, updates on subsequent calls.
INSERT INTO provider_availability (staff_id)
VALUES ($1)
ON CONFLICT (staff_id) DO UPDATE
    SET updated_at = NOW()
RETURNING *;


-- ============================================
-- STATUS TRANSITIONS
-- ============================================

-- name: GoOnline :one
-- Provider opens their dashboard.
UPDATE provider_availability
SET
    is_online   = true,
    shift_start = COALESCE(shift_start, NOW()),
    last_seen_at = NOW(),
    updated_at  = NOW()
WHERE staff_id = $1
RETURNING *;

-- name: GoOffline :exec
-- Provider closes dashboard or session expires.
UPDATE provider_availability
SET
    is_online    = false,
    is_accepting = false,
    status       = 'offline',
    shift_start  = NULL,
    updated_at   = NOW()
WHERE staff_id = $1;

-- name: SetAccepting :one
-- Provider toggles "Start Accepting" in their UI.
UPDATE provider_availability
SET
    is_accepting          = $2,
    status                = CASE WHEN $2 THEN 'available' ELSE 'away' END,
    consultation_fee_override = COALESCE($3, consultation_fee_override),
    estimated_wait_minutes    = COALESCE($4, estimated_wait_minutes),
    updated_at            = NOW()
WHERE staff_id = $1
RETURNING *;

-- name: UpdateStatus :exec
UPDATE provider_availability
SET
    status         = $2,
    status_message = $3,
    updated_at     = NOW()
WHERE staff_id = $1;

-- name: UpdateHeartbeat :exec
-- Provider dashboard pings every 30 s. If last_seen_at is stale (> 2 min),
-- a background job sets the provider offline.
UPDATE provider_availability
SET last_seen_at = NOW()
WHERE staff_id = $1;


-- ============================================
-- CONCURRENCY COUNTERS
-- ============================================

-- name: IncrementActiveConsultations :one
-- Called atomically when a provider accepts a consultation.
-- Returns the updated row so the service layer can enforce the cap.
UPDATE provider_availability
SET
    active_consultation_count = active_consultation_count + 1,
    status = CASE
        WHEN active_consultation_count + 1 >= max_concurrent_consultations THEN 'busy'
        ELSE 'available'
    END,
    updated_at = NOW()
WHERE
    staff_id = $1
    AND active_consultation_count < max_concurrent_consultations
RETURNING *;

-- name: DecrementActiveConsultations :exec
-- Called when a consultation closes (completed / cancelled / no_show).
UPDATE provider_availability
SET
    active_consultation_count = GREATEST(active_consultation_count - 1, 0),
    status = CASE
        WHEN is_accepting AND GREATEST(active_consultation_count - 1, 0) < max_concurrent_consultations
            THEN 'available'
        WHEN NOT is_accepting
            THEN 'away'
        ELSE status
    END,
    updated_at = NOW()
WHERE staff_id = $1;

-- name: SetMaxConcurrent :exec
UPDATE provider_availability
SET
    max_concurrent_consultations = $2,
    updated_at = NOW()
WHERE staff_id = $1;


-- ============================================
-- PROVIDER LIST (Patient-facing)
-- ============================================

-- name: GetAvailableProviders :many
-- Powers ProvidersList.jsx — only providers who are accepting AND have capacity.
SELECT
    pa.staff_id,
    pa.status,
    pa.estimated_wait_minutes,
    pa.active_consultation_count,
    pa.max_concurrent_consultations,
    pa.consultation_fee_override,
    pa.status_message,

    cs.title,
    cs.first_name,
    cs.last_name,
    cs.professional_title,
    cs.specialization,
    cs.bio,
    cs.profile_picture_url,
    cs.years_experience,
    cs.languages_spoken
FROM provider_availability pa
JOIN clinic_staff cs ON cs.id = pa.staff_id
WHERE
    pa.is_accepting = true
    AND pa.is_online = true
    AND pa.active_consultation_count < pa.max_concurrent_consultations
    AND cs.employment_status = 'active'
    AND ($1::uuid IS NULL OR cs.clinic_id = $1)   -- optional clinic filter
ORDER BY
    pa.estimated_wait_minutes ASC NULLS LAST,
    pa.active_consultation_count ASC;

-- name: GetAvailableProvidersBySpecialization :many
-- Filtered version: patient requests a specific specialty.
SELECT
    pa.staff_id,
    pa.status,
    pa.estimated_wait_minutes,
    pa.consultation_fee_override,
    cs.first_name,
    cs.last_name,
    cs.professional_title,
    cs.specialization,
    cs.profile_picture_url,
    cs.years_experience
FROM provider_availability pa
JOIN clinic_staff cs ON cs.id = pa.staff_id
WHERE
    pa.is_accepting = true
    AND pa.is_online = true
    AND pa.active_consultation_count < pa.max_concurrent_consultations
    AND cs.employment_status = 'active'
    AND cs.specialization ILIKE '%' || $1 || '%'
ORDER BY pa.estimated_wait_minutes ASC NULLS LAST;


-- ============================================
-- PROVIDER-FACING SELF-READS
-- ============================================

-- name: GetAvailabilityByStaffID :one
SELECT * FROM provider_availability
WHERE staff_id = $1;

-- name: UpdateWaitTime :exec
-- Provider manually adjusts their estimated wait time shown to patients.
UPDATE provider_availability
SET
    estimated_wait_minutes = $2,
    updated_at             = NOW()
WHERE staff_id = $1;


-- ============================================
-- BACKGROUND JOB QUERIES
-- ============================================

-- name: GetStaleProviders :many
-- Background job: find providers whose heartbeat hasn't been seen in 2 minutes.
-- Used to auto-set them offline so patients don't wait for a ghost provider.
SELECT staff_id
FROM provider_availability
WHERE
    is_online    = true
    AND last_seen_at < NOW() - INTERVAL '2 minutes';

-- name: SetStaleProvidersOffline :exec
-- Companion to GetStaleProviders — runs in same background job.
UPDATE provider_availability
SET
    is_online    = false,
    is_accepting = false,
    status       = 'offline',
    shift_start  = NULL,
    updated_at   = NOW()
WHERE
    is_online    = true
    AND last_seen_at < NOW() - INTERVAL '2 minutes';
