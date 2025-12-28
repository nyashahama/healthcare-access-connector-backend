-- ============================================
-- Audit Logging Queries (POPIA Compliance)
-- ============================================

-- name: LogUserActivity :exec
INSERT INTO user_activities (
    user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, resource_type, resource_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);


-- name: GetUserActivities :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    device_type, resource_type, resource_id, performed_at
FROM user_activities
WHERE user_id = $1
ORDER BY performed_at DESC
LIMIT $2 OFFSET $3;


