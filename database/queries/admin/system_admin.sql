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

