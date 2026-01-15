-- User Management Queries
-- name: CreateUser :one
INSERT INTO users (
    email, phone, password_hash, role, status, 
    is_sms_only, sms_consent_given, popia_consent_given, consent_date
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, email, phone, role, status, is_verified, last_login, 
    login_count, is_sms_only, profile_completion_percentage, created_at, updated_at;

-- name: GetUserByVerificationToken :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    verification_token, verification_expires, last_login, login_count, 
    is_sms_only, sms_consent_given, popia_consent_given, 
    profile_completion_percentage, created_at, updated_at
FROM users
WHERE verification_token = $1 
    AND verification_expires > NOW() 
    AND status != 'inactive';

-- name: GetUserByPasswordResetToken :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    reset_password_token, reset_password_expires, last_login, login_count, 
    is_sms_only, sms_consent_given, popia_consent_given, 
    profile_completion_percentage, created_at, updated_at
FROM users
WHERE reset_password_token = $1 
    AND reset_password_expires > NOW() 
    AND status != 'inactive';

-- name: GetUserByEmail :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    verification_token, verification_expires, last_login, login_count, 
    is_sms_only, sms_consent_given, popia_consent_given, 
    profile_completion_percentage, created_at, updated_at
FROM users
WHERE email = $1 AND status != 'inactive';

-- name: GetUserByPhone :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    last_login, login_count, is_sms_only, sms_consent_given, 
    popia_consent_given, profile_completion_percentage, created_at, updated_at
FROM users
WHERE phone = $1 AND status != 'inactive';

-- name: GetUserByPhoneWithHash :one
SELECT id, email, phone, password_hash, role, status, is_verified, 
    last_login, login_count, is_sms_only, sms_consent_given, 
    popia_consent_given, profile_completion_percentage, 
    created_at, updated_at
FROM users
WHERE phone = $1 AND status != 'inactive';

-- name: GetUserByID :one
SELECT id, email, phone, role, status, is_verified, last_login, 
    login_count, is_sms_only, profile_completion_percentage, 
    created_at, updated_at
FROM users
WHERE id = $1 AND status != 'inactive';

-- name: UpdateUserLastLogin :exec
UPDATE users
SET last_login = NOW(), login_count = login_count + 1
WHERE id = $1;

-- name: UpdateUserStatus :exec
UPDATE users
SET status = $2, updated_at = NOW()
WHERE id = $1;

-- name: VerifyUser :exec
UPDATE users
SET is_verified = TRUE, verification_token = NULL, verification_expires = NULL, updated_at = NOW()
WHERE id = $1;

-- name: SetVerificationToken :exec
UPDATE users
SET verification_token = $2, verification_expires = $3, updated_at = NOW()
WHERE id = $1;

-- name: SetPasswordResetToken :exec
UPDATE users
SET reset_password_token = $2, reset_password_expires = $3, updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET password_hash = $2, reset_password_token = NULL, reset_password_expires = NULL, updated_at = NOW()
WHERE id = $1;

-- name: ListUsersByRole :many
SELECT id, email, phone, role, status, is_verified, last_login, 
    profile_completion_percentage, created_at
FROM users
WHERE role = $1 AND status != 'inactive'
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: CountUsersByRole :one
SELECT COUNT(*) FROM users 
WHERE role = $1 AND status != 'inactive';

-- name: UpdateUser :exec
UPDATE users
SET 
    email = COALESCE($2, email),
    phone = COALESCE($3, phone),
    role = COALESCE($4, role),
    status = COALESCE($5, status),
    is_sms_only = COALESCE($6, is_sms_only),
    sms_consent_given = COALESCE($7, sms_consent_given),
    popia_consent_given = COALESCE($8, popia_consent_given),
    consent_date = COALESCE($9, consent_date),
    profile_completion_percentage = COALESCE($10, profile_completion_percentage),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserEmail :exec
UPDATE users
SET email = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserPhone :exec
UPDATE users
SET phone = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserProfileCompletion :exec
UPDATE users
SET profile_completion_percentage = $2, updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserConsents :exec
UPDATE users
SET 
    sms_consent_given = $2,
    popia_consent_given = $3,
    consent_date = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateUserRole :exec
UPDATE users
SET role = $2, updated_at = NOW()
WHERE id = $1;

-- name: SearchUsers :many
SELECT id, email, phone, role, status, is_verified, last_login, 
    profile_completion_percentage, created_at
FROM users
WHERE status != 'inactive'
    AND (
        $1 = '' OR 
        email ILIKE '%' || $1 || '%' OR 
        phone ILIKE '%' || $1 || '%'
    )
    AND ($2 = '' OR role = $2)
    AND ($3 = '' OR status = $3)
ORDER BY created_at DESC;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: BulkUpdateUserStatus :exec
UPDATE users
SET status = $2, updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: GetUsersByIDs :many
SELECT id, email, phone, role, status, is_verified, last_login, 
    login_count, is_sms_only, profile_completion_percentage, 
    created_at, updated_at
FROM users
WHERE id = ANY($1::uuid[]) AND status != 'inactive'
ORDER BY created_at DESC;
