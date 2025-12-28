-- Session Management Queries
-- name: CreateSession :one
INSERT INTO user_sessions (
    user_id, session_token, device_type, device_id, 
    ip_address, user_agent, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, session_token, expires_at, created_at;

-- name: GetSession :one
SELECT id, user_id, session_token, device_type, ip_address, 
    user_agent, expires_at, created_at
FROM user_sessions
WHERE session_token = $1 AND expires_at > NOW();

-- name: DeleteSession :exec
DELETE FROM user_sessions WHERE session_token = $1;

-- name: DeleteUserSessions :exec
DELETE FROM user_sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM user_sessions WHERE expires_at <= NOW();

-- name: UpdateSessionToken :exec
UPDATE user_sessions
SET session_token = $2, expires_at = $3
WHERE id = $1;