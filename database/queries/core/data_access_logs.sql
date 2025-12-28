
-- name: LogDataAccess :exec
INSERT INTO data_access_logs (
    accessed_by_user_id, accessed_by_role, accessed_user_id,
    accessed_resource_type, accessed_resource_id, access_type,
    access_reason, is_emergency_access, ip_address, user_agent
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);


-- name: GetDataAccessLogs :many
SELECT id, accessed_by_user_id, accessed_by_role, accessed_resource_type,
    accessed_resource_id, access_type, access_reason, 
    is_emergency_access, accessed_at
FROM data_access_logs
WHERE accessed_user_id = $1
ORDER BY accessed_at DESC
LIMIT $2 OFFSET $3;
