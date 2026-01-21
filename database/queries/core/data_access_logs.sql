-- ============================================
-- Data Access Log Queries
-- ============================================

-- name: LogDataAccess :exec
INSERT INTO data_access_logs (
    accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent,
    location
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetDataAccessLogs :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent,
    location, accessed_at
FROM data_access_logs
WHERE accessed_user_id = $1
ORDER BY accessed_at DESC
LIMIT $2 OFFSET $3;

-- name: GetEmergencyAccessLogs :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent,
    location, accessed_at
FROM data_access_logs
WHERE is_emergency_access = true
ORDER BY accessed_at DESC
LIMIT $1 OFFSET $2;

-- name: SearchDataAccessLogs :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent,
    location, accessed_at
FROM data_access_logs
WHERE ($1::uuid IS NULL OR accessed_user_id = $1)
    AND ($2::uuid IS NULL OR accessed_by_user_id = $2)
    AND ($3::varchar IS NULL OR access_type = $3)
    AND ($4::varchar IS NULL OR accessed_resource_type = $4)
    AND ($5::boolean IS NULL OR is_emergency_access = $5)
    AND ($6::timestamp IS NULL OR accessed_at >= $6)
    AND ($7::timestamp IS NULL OR accessed_at <= $7)
ORDER BY accessed_at DESC
LIMIT $8 OFFSET $9;

-- name: GetAccessLogsByAccessedByUser :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent,
    location, accessed_at
FROM data_access_logs
WHERE accessed_by_user_id = $1
ORDER BY accessed_at DESC
LIMIT $2 OFFSET $3;

-- name: ExportDataAccessLogs :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent,
    location, accessed_at
FROM data_access_logs
WHERE accessed_user_id = $1
    AND accessed_at >= $2
    AND accessed_at <= $3
ORDER BY accessed_at DESC;

-- name: DeleteOldDataAccessLogs :exec
DELETE FROM data_access_logs
WHERE accessed_at < $1;
