-- name: CreateAppointment :one
INSERT INTO appointments (
    clinic_id,
    patient_id,
    appointment_date,
    appointment_time,
    appointment_datetime,
    patient_name,
    patient_phone,
    patient_email,
    reason_for_visit,
    notes,
    status
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)
RETURNING *;

-- name: GetAppointment :one
SELECT *
FROM appointments
WHERE id = $1;

-- name: GetAppointmentsByPatient :many
SELECT *
FROM appointments
WHERE patient_id = $1
ORDER BY appointment_datetime DESC;

-- name: GetAppointmentsByClinic :many
SELECT *
FROM appointments
WHERE clinic_id = $1
  AND appointment_date >= CURRENT_DATE
ORDER BY appointment_datetime ASC;

-- name: GetAppointmentsByClinicAndDate :many
SELECT *
FROM appointments
WHERE clinic_id = $1
  AND appointment_date = $2
ORDER BY appointment_time ASC;

-- -- name: GetUpcomingAppointments :many
-- SELECT *
-- FROM appointments
-- WHERE patient_id = $1
--   AND appointment_datetime >= CURRENT_TIMESTAMP
--   AND appointment_datetime <= CURRENT_TIMESTAMP + INTERVAL '7 days'
--   AND status NOT IN ('cancelled', 'completed')
-- ORDER BY appointment_datetime ASC;

-- name: GetTodayAppointments :many
SELECT *
FROM appointments
WHERE clinic_id = $1
  AND appointment_date = CURRENT_DATE
ORDER BY appointment_time ASC;

-- name: RescheduleAppointment :one
UPDATE appointments
SET 
    appointment_date = $2,
    appointment_time = $3,
    appointment_datetime = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
  AND status IN ('pending', 'confirmed')
RETURNING *;

-- name: ConfirmAppointment :one
UPDATE appointments
SET 
    status = 'confirmed',
    confirmed_by = $2,
    confirmed_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
  AND status = 'pending'
RETURNING *;

-- name: UpdateAppointmentNotes :one
UPDATE appointments
SET 
    notes = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;

-- name: CompleteAppointment :one
UPDATE appointments
SET 
    status = 'completed',
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
  AND appointment_datetime < CURRENT_TIMESTAMP
RETURNING *;

-- name: CancelAppointment :one
UPDATE appointments
SET 
    status = 'cancelled',
    cancellation_reason = $2,
    cancelled_by = $3,
    cancelled_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
  AND status IN ('pending', 'confirmed')
RETURNING *;

-- name: DeleteAppointment :exec
DELETE FROM appointments
WHERE id = $1
  AND status = 'cancelled';

-- name: CheckSchedulingConflict :one
SELECT id, patient_name, appointment_time
FROM appointments
WHERE clinic_id = $1
  AND appointment_date = $2
  AND appointment_time = $3
  AND status NOT IN ('cancelled', 'no_show')
LIMIT 1;

-- name: GetAppointmentCount :one
SELECT COUNT(*) as total_appointments
FROM appointments
WHERE patient_id = $1
  AND status = 'completed';

-- name: GetPendingAppointments :many
SELECT *
FROM appointments
WHERE clinic_id = $1
  AND status = 'pending'
ORDER BY appointment_datetime ASC;

-- name: UpdateAppointmentStatus :one
UPDATE appointments
SET 
    status = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
RETURNING *;
