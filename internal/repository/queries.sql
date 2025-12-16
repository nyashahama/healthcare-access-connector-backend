-- User queries

-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, role)
VALUES ($1, $2, $3, $4)
RETURNING id, username, email, role, created_at, updated_at, is_active, email_verified;

-- name: GetUserByEmail :one
SELECT id, username, email, password_hash, role, created_at, updated_at, last_login, is_active, email_verified
FROM users
WHERE email = $1 AND is_active = TRUE;

-- name: GetUserByID :one
SELECT id, username, email, role, created_at, updated_at, last_login, is_active, email_verified
FROM users
WHERE id = $1 AND is_active = TRUE;

-- name: GetUserByUsername :one
SELECT id, username, email, role, created_at, updated_at, last_login, is_active, email_verified
FROM users
WHERE username = $1 AND is_active = TRUE;

-- name: UpdateUserLastLogin :exec
UPDATE users
SET last_login = NOW()
WHERE id = $1;

-- name: UpdateUserEmail :exec
UPDATE users
SET email = $1
WHERE id = $2;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $1
WHERE id = $2;

-- name: VerifyUserEmail :exec
UPDATE users
SET email_verified = TRUE
WHERE id = $1;

-- name: DeactivateUser :exec
UPDATE users
SET is_active = FALSE
WHERE id = $1;

-- name: ListUsers :many
SELECT id, username, email, role, created_at, updated_at, last_login, is_active, email_verified
FROM users
WHERE is_active = TRUE
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*) FROM users WHERE is_active = TRUE;

-- Session queries

-- name: CreateSession :one
INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, expires_at, created_at;

-- name: GetSession :one
SELECT id, user_id, token_hash, expires_at, created_at, ip_address, user_agent
FROM sessions
WHERE id = $1 AND expires_at > NOW();

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions WHERE expires_at <= NOW();

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- Audit log queries

-- name: CreateAuditLog :exec
INSERT INTO audit_logs (user_id, action, resource, details, ip_address)
VALUES ($1, $2, $3, $4, $5);

-- name: GetUserAuditLogs :many
SELECT id, user_id, action, resource, details, ip_address, created_at
FROM audit_logs
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;