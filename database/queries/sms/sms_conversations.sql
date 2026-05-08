-- ============================================
-- SMS Conversation Queries
-- ============================================

-- name: CreateSMSConversation :one
INSERT INTO sms_conversations (
    user_id, phone_number, current_menu, conversation_state
)
VALUES ($1, $2, $3, $4)
RETURNING id, user_id, phone_number, created_at;

-- name: GetSMSConversationByPhone :one
SELECT id, user_id, phone_number, current_menu, conversation_state, last_message_sent,
    last_message_received, last_interaction_at, last_location, last_search_query,
    callback_scheduled, created_at, updated_at
FROM sms_conversations
WHERE phone_number = $1
ORDER BY COALESCE(last_interaction_at, created_at) DESC, created_at DESC, id DESC
LIMIT 1;

-- name: GetSMSConversation :one
SELECT * FROM sms_conversations WHERE id = $1;

-- name: GetSMSConversationByUserID :one
SELECT id, user_id, phone_number, current_menu, conversation_state, last_message_sent,
    last_message_received, last_interaction_at, last_location, last_search_query,
    callback_scheduled, created_at, updated_at
FROM sms_conversations
WHERE user_id = $1
ORDER BY COALESCE(last_interaction_at, created_at) DESC, created_at DESC, id DESC
LIMIT 1;

-- name: GetActiveSMSConversations :many
SELECT * FROM sms_conversations
WHERE (current_menu IS NULL OR LOWER(current_menu) <> 'closed')
ORDER BY COALESCE(last_interaction_at, created_at) DESC;

-- name: UpdateSMSConversation :exec
UPDATE sms_conversations
SET current_menu = $2, conversation_state = $3,
    last_message_sent = $4, last_message_received = $5,
    last_interaction_at = NOW()
WHERE id = $1;

-- name: CloseSMSConversation :exec
UPDATE sms_conversations
SET current_menu = 'closed',
    conversation_state = COALESCE(conversation_state, '{}'::jsonb) ||
      jsonb_build_object('is_closed', true, 'closed_at', NOW(), 'closed_reason', $2),
    last_interaction_at = NOW()
WHERE id = $1;

-- name: ArchiveOldSMSMessages :exec
DELETE FROM sms_messages
WHERE created_at < NOW() - make_interval(secs => $1);

