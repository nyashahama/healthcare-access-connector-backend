-- ============================================
-- Notification Preferences Queries
-- ============================================

-- name: CreateNotificationPreferences :one
INSERT INTO notification_preferences (
    user_id, sms_enabled, email_enabled, push_enabled,
    appointment_reminders, health_tips, notification_language
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, created_at;


-- name: GetNotificationPreferences :one
SELECT * FROM notification_preferences WHERE user_id = $1;


-- name: UpdateNotificationPreferences :exec
UPDATE notification_preferences
SET sms_enabled = $2, email_enabled = $3, push_enabled = $4,
    appointment_reminders = $5, health_tips = $6,
    medication_reminders = $7, emergency_alerts = $8
WHERE user_id = $1;


-- name: DeleteNotificationPreferences :exec
DELETE FROM notification_preferences WHERE user_id = $1;

-- name: UpdateChannelSettings :exec
UPDATE notification_preferences
SET 
    sms_enabled = $2,
    email_enabled = $3,
    push_enabled = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateAppointmentReminders :exec
UPDATE notification_preferences
SET 
    appointment_reminders = $2,
    appointment_reminder_hours_before = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateHealthTips :exec
UPDATE notification_preferences
SET 
    health_tips = $2,
    health_tips_frequency = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateMedicationReminders :exec
UPDATE notification_preferences
SET 
    medication_reminders = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateEmergencyAlerts :exec
UPDATE notification_preferences
SET 
    emergency_alerts = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateQuietHours :exec
UPDATE notification_preferences
SET 
    quiet_hours_start = $2,
    quiet_hours_end = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateNotificationLanguage :exec
UPDATE notification_preferences
SET 
    notification_language = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: GetUsersWithDisabledType :many
SELECT user_id FROM notification_preferences 
WHERE 
    (CASE 
        WHEN $1 = 'sms' THEN NOT sms_enabled
        WHEN $1 = 'email' THEN NOT email_enabled
        WHEN $1 = 'push' THEN NOT push_enabled
        WHEN $1 = 'appointment_reminders' THEN NOT appointment_reminders
        WHEN $1 = 'health_tips' THEN NOT health_tips
        WHEN $1 = 'medication_reminders' THEN NOT medication_reminders
        WHEN $1 = 'emergency_alerts' THEN NOT emergency_alerts
        ELSE false
    END);

-- name: GetUsersForHealthTips :many
SELECT user_id FROM notification_preferences 
WHERE health_tips = true AND health_tips_frequency = $1;
