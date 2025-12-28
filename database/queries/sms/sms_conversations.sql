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
SELECT * FROM sms_conversations WHERE phone_number = $1;


-- name: UpdateSMSConversation :exec
UPDATE sms_conversations
SET current_menu = $2, conversation_state = $3,
    last_message_sent = $4, last_message_received = $5,
    last_interaction_at = NOW()
WHERE id = $1;



