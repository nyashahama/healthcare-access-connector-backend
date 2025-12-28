-- name: LogSMSMessage :one
INSERT INTO sms_messages (
    conversation_id, direction, message_body, twilio_message_id,
    twilio_status, segments, cost, cost_currency
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, conversation_id, direction, created_at;


-- name: GetConversationMessages :many
SELECT id, conversation_id, direction, message_body, 
    twilio_status, sent_at, delivered_at, created_at
FROM sms_messages
WHERE conversation_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;
