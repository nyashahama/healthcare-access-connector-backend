-- ============================================
-- User Activity Queries
-- ============================================

-- name: LogUserActivity :exec
INSERT INTO user_activities (
    user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location, 
    resource_type, resource_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetUserActivities :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location,
    resource_type, resource_id, performed_at
FROM user_activities
WHERE user_id = $1
ORDER BY performed_at DESC
LIMIT $2 OFFSET $3;

-- name: GetActivitiesByType :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location,
    resource_type, resource_id, performed_at
FROM user_activities
WHERE activity_type = $1
    AND performed_at >= $2
    AND performed_at <= $3
ORDER BY performed_at DESC;

-- name: GetActivitiesByResource :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location,
    resource_type, resource_id, performed_at
FROM user_activities
WHERE resource_type = $1
    AND resource_id = $2
ORDER BY performed_at DESC;

-- name: SearchUserActivities :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location,
    resource_type, resource_id, performed_at
FROM user_activities
WHERE ($1::uuid IS NULL OR user_id = $1)
    AND ($2::varchar IS NULL OR activity_type = $2)
    AND ($3::varchar IS NULL OR resource_type = $3)
    AND ($4::timestamp IS NULL OR performed_at >= $4)
    AND ($5::timestamp IS NULL OR performed_at <= $5)
ORDER BY performed_at DESC
LIMIT $6 OFFSET $7;

-- name: GetRecentActivities :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location,
    resource_type, resource_id, performed_at
FROM user_activities
WHERE performed_at >= $1
ORDER BY performed_at DESC
LIMIT $2 OFFSET $3;

-- name: ExportUserActivities :many
SELECT id, user_id, activity_type, activity_details, ip_address,
    user_agent, device_type, device_id, location,
    resource_type, resource_id, performed_at
FROM user_activities
WHERE user_id = $1
    AND performed_at >= $2
    AND performed_at <= $3
ORDER BY performed_at DESC;

-- name: DeleteOldUserActivities :exec
DELETE FROM user_activities
WHERE performed_at < $1;
