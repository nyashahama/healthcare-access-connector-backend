-- OTP Verification Queries
-- name: SaveOTP :one
INSERT INTO otp_verifications (id, user_id, otp, type, channel, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, otp, type, channel, expires_at, used_at, created_at;

-- name: GetOTP :one
SELECT id, user_id, otp, type, channel, expires_at, used_at, created_at
FROM otp_verifications
WHERE user_id = $1 
    AND otp = $2 
    AND type = $3 
    AND used_at IS NULL
    AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT 1;

-- name: MarkOTPUsed :exec
UPDATE otp_verifications
SET used_at = $2
WHERE id = $1;

-- name: DeleteExpiredOTPs :exec
DELETE FROM otp_verifications
WHERE expires_at < NOW() OR created_at < NOW() - INTERVAL '24 hours';

-- name: DeleteUserOTPs :exec
DELETE FROM otp_verifications
WHERE user_id = $1 AND type = $2;

-- name: GetOTPAttemptCount :one
SELECT COUNT(*) 
FROM otp_verifications
WHERE user_id = $1 
    AND type = $2 
    AND created_at > NOW() - INTERVAL '1 hour';