-- ============================================
-- CORE WRITE OPERATIONS
-- ============================================

-- name: InsertMessage :one
INSERT INTO consultation_messages (
    consultation_id, sender_user_id, sender_role,
    message_type, content,
    attachment_url, attachment_type, attachment_filename,
    metadata
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb
)
RETURNING *;

-- name: SoftDeleteMessage :exec
-- Hides content from both parties while preserving the audit record.
UPDATE consultation_messages
SET
    content          = NULL,
    attachment_url   = NULL,
    is_deleted       = true
WHERE id = $1
  AND is_deleted = false;


-- ============================================
-- READ OPERATIONS
-- ============================================

-- name: GetMessageByID :one
SELECT * FROM consultation_messages
WHERE id = $1 AND is_deleted = false;

-- name: GetConsultationMessages :many
-- Full message thread for a consultation — used on initial chat load.
SELECT
    id, consultation_id, sender_user_id, sender_role,
    message_type, content,
    attachment_url, attachment_type, attachment_filename,
    is_read, read_at, metadata, sent_at
FROM consultation_messages
WHERE
    consultation_id = $1
    AND is_deleted  = false
ORDER BY sent_at ASC
LIMIT  $2
OFFSET $3;

-- name: GetMessagesAfterCursor :many
-- Polling / WebSocket catch-up: messages newer than a timestamp cursor.
SELECT
    id, sender_user_id, sender_role,
    message_type, content,
    attachment_url, attachment_type, attachment_filename,
    is_read, metadata, sent_at
FROM consultation_messages
WHERE
    consultation_id = $1
    AND sent_at     > $2
    AND is_deleted  = false
ORDER BY sent_at ASC;

-- name: GetLastMessage :one
-- Used in consultation list previews.
SELECT
    id, sender_role, message_type, content, attachment_type, sent_at
FROM consultation_messages
WHERE
    consultation_id = $1
    AND is_deleted  = false
ORDER BY sent_at DESC
LIMIT 1;


-- ============================================
-- READ RECEIPTS
-- ============================================

-- name: MarkMessageRead :exec
UPDATE consultation_messages
SET
    is_read = true,
    read_at = NOW()
WHERE id = $1
  AND is_read = false;

-- name: MarkAllProviderMessagesRead :exec
-- Patient opens chat → mark all provider messages as read.
UPDATE consultation_messages
SET
    is_read = true,
    read_at = NOW()
WHERE
    consultation_id = $1
    AND sender_role = 'provider'
    AND is_read     = false
    AND is_deleted  = false;

-- name: MarkAllPatientMessagesRead :exec
-- Provider opens chat → mark all patient messages as read.
UPDATE consultation_messages
SET
    is_read = true,
    read_at = NOW()
WHERE
    consultation_id = $1
    AND sender_role = 'patient'
    AND is_read     = false
    AND is_deleted  = false;

-- name: CountUnreadMessages :one
-- Badge counter for a given party (pass sender_role of the OTHER party).
SELECT COUNT(*) AS unread_count
FROM consultation_messages
WHERE
    consultation_id = $1
    AND sender_role = $2
    AND is_read     = false
    AND is_deleted  = false;


-- ============================================
-- SYSTEM / SPECIAL MESSAGE HELPERS
-- ============================================

-- name: InsertSystemEvent :one
-- Convenience for system-generated events (call start, file shared, chat ended).
INSERT INTO consultation_messages (
    consultation_id, sender_user_id, sender_role,
    message_type, content, metadata
)
VALUES (
    $1,
    $2,           -- system bot user_id (pass a fixed system UUID from config)
    'system',
    'system_event',
    $3,           -- human-readable label e.g. "Chat started"
    $4::jsonb     -- structured event data e.g. {"event": "video_call_started", "room_sid": "..."}
)
RETURNING *;

-- name: GetSystemEvents :many
-- Retrieve only system events for a consultation (call log, file shares).
SELECT
    id, content, metadata, sent_at
FROM consultation_messages
WHERE
    consultation_id = $1
    AND message_type = 'system_event'
ORDER BY sent_at ASC;


-- ============================================
-- ATTACHMENTS
-- ============================================

-- name: GetConsultationAttachments :many
-- All files shared in a consultation — shown in the attachment list panel.
SELECT
    id, sender_user_id, sender_role,
    attachment_url, attachment_type, attachment_filename,
    sent_at
FROM consultation_messages
WHERE
    consultation_id = $1
    AND message_type = 'attachment'
    AND is_deleted   = false
ORDER BY sent_at ASC;
