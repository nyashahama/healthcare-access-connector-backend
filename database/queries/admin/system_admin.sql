-- ============================================
-- SYSTEM ADMINS REPOSITORY QUERIES
-- Maps to: AdminRepository interface
-- Domain: System Administration & Access Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateSystemAdmin :one
INSERT INTO system_admins (
    user_id, admin_level, assigned_regions, department,
    permissions, can_manage_users, can_manage_clinics,
    can_manage_content, can_view_analytics, can_manage_system,
    work_phone, extension
)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetSystemAdmin :one
SELECT * FROM system_admins
WHERE id = $1;

-- name: GetSystemAdminByUserID :one
SELECT * FROM system_admins
WHERE user_id = $1;

-- name: DeleteSystemAdmin :exec
DELETE FROM system_admins
WHERE id = $1;

-- name: DeleteSystemAdminByUserID :exec
DELETE FROM system_admins
WHERE user_id = $1;

-- name: UpdateSystemAdmin :one
UPDATE system_admins
SET
    admin_level = $2,
    assigned_regions = $3,
    department = $4,
    permissions = $5::jsonb,
    can_manage_users = $6,
    can_manage_clinics = $7,
    can_manage_content = $8,
    can_view_analytics = $9,
    can_manage_system = $10,
    work_phone = $11,
    extension = $12,
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SearchSystemAdmins :many
SELECT * FROM system_admins
WHERE
    ($1 = '' OR admin_level = $1)
    AND ($2 = '' OR $2 = ANY(assigned_regions))
    AND ($3 = '' OR department ILIKE '%' || $3 || '%')
    AND (
        $4 = '' OR
        admin_level ILIKE '%' || $4 || '%' OR
        department ILIKE '%' || $4 || '%' OR
        user_id::text ILIKE '%' || $4 || '%' OR
        id::text ILIKE '%' || $4 || '%'
    )
ORDER BY created_at DESC
LIMIT $5
OFFSET $6;
