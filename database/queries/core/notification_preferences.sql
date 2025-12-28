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

