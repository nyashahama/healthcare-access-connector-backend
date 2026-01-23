-- Session Management Queries
-- name: CreateSession :one
INSERT INTO user_sessions (
    user_id, session_token, device_type, device_id, 
    ip_address, user_agent, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, session_token, device_type, device_id, 
    ip_address, user_agent, expires_at, created_at;

-- name: GetSession :one
SELECT id, user_id, session_token, device_type, ip_address, 
    user_agent, expires_at, created_at
FROM user_sessions
WHERE session_token = $1 AND expires_at > NOW();

-- name: GetUserSessions :many
SELECT id, user_id, session_token, device_type, device_id, 
    ip_address, user_agent, expires_at, created_at
FROM user_sessions
WHERE user_id = $1 AND expires_at > NOW()
ORDER BY created_at DESC;

-- name: DeleteSession :exec
DELETE FROM user_sessions WHERE session_token = $1;

-- name: DeleteUserSessions :exec
DELETE FROM user_sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM user_sessions WHERE expires_at <= NOW();

-- name: DeleteSessionByDevice :exec
DELETE FROM user_sessions 
WHERE user_id = $1 AND device_id = $2;

-- name: DeleteAllSessionsExcept :exec
DELETE FROM user_sessions 
WHERE user_id = $1 AND id != $2;

-- name: UpdateSessionToken :exec
UPDATE user_sessions
SET session_token = $2, expires_at = $3
WHERE id = $1;


-- name: UpdateSession :exec
UPDATE user_sessions
SET 
    device_type = COALESCE($2, device_type),
    device_id = COALESCE($3, device_id),
    ip_address = COALESCE($4, ip_address),
    user_agent = COALESCE($5, user_agent),
    expires_at = COALESCE($6, expires_at)
WHERE id = $1;

