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

-- name: UpdateSystemAdmin :exec
UPDATE system_admins
SET 
    admin_level = COALESCE($2, admin_level),
    assigned_regions = COALESCE($3, assigned_regions),
    department = COALESCE($4, department),
    permissions = COALESCE($5, permissions),
    work_phone = COALESCE($6, work_phone),
    extension = COALESCE($7, extension),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteSystemAdmin :exec
DELETE FROM system_admins WHERE id = $1;

-- ============================================
-- PERMISSIONS MANAGEMENT
-- ============================================

-- name: UpdateAdminPermissions :exec
UPDATE system_admins
SET 
    permissions = $2,
    can_manage_users = $3,
    can_manage_clinics = $4,
    can_manage_content = $5,
    can_view_analytics = $6,
    can_manage_system = $7,
    updated_at = NOW()
WHERE id = $1;

-- name: GrantUserManagement :exec
UPDATE system_admins
SET 
    can_manage_users = true,
    permissions = jsonb_set(permissions, '{manage_users}', 'true', true),
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeUserManagement :exec
UPDATE system_admins
SET 
    can_manage_users = false,
    permissions = jsonb_set(permissions, '{manage_users}', 'false', true),
    updated_at = NOW()
WHERE id = $1;

-- name: GrantClinicManagement :exec
UPDATE system_admins
SET 
    can_manage_clinics = true,
    permissions = jsonb_set(permissions, '{manage_clinics}', 'true', true),
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeClinicManagement :exec
UPDATE system_admins
SET 
    can_manage_clinics = false,
    permissions = jsonb_set(permissions, '{manage_clinics}', 'false', true),
    updated_at = NOW()
WHERE id = $1;

-- name: GrantContentManagement :exec
UPDATE system_admins
SET 
    can_manage_content = true,
    permissions = jsonb_set(permissions, '{manage_content}', 'true', true),
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeContentManagement :exec
UPDATE system_admins
SET 
    can_manage_content = false,
    permissions = jsonb_set(permissions, '{manage_content}', 'false', true),
    updated_at = NOW()
WHERE id = $1;

-- name: GrantAnalyticsAccess :exec
UPDATE system_admins
SET 
    can_view_analytics = true,
    permissions = jsonb_set(permissions, '{view_analytics}', 'true', true),
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeAnalyticsAccess :exec
UPDATE system_admins
SET 
    can_view_analytics = false,
    permissions = jsonb_set(permissions, '{view_analytics}', 'false', true),
    updated_at = NOW()
WHERE id = $1;

-- name: GrantSystemManagement :exec
UPDATE system_admins
SET 
    can_manage_system = true,
    permissions = jsonb_set(permissions, '{manage_system}', 'true', true),
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeSystemManagement :exec
UPDATE system_admins
SET 
    can_manage_system = false,
    permissions = jsonb_set(permissions, '{manage_system}', 'false', true),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdatePermissionsJSON :exec
UPDATE system_admins
SET 
    permissions = $2,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- ADMIN LEVEL QUERIES
-- ============================================

-- name: GetAdminsByLevel :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    u.phone,
    sa.admin_level,
    sa.department,
    sa.assigned_regions,
    sa.work_phone,
    sa.created_at
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.admin_level = $1
ORDER BY sa.created_at DESC;

-- name: GetSuperAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    u.phone,
    sa.department,
    sa.work_phone,
    sa.created_at
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.admin_level = 'super_admin'
ORDER BY sa.created_at DESC;

-- name: GetRegionalAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.assigned_regions,
    sa.department,
    sa.work_phone
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.admin_level = 'regional_admin'
ORDER BY sa.created_at DESC;

-- name: GetSupportAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.department,
    sa.work_phone,
    sa.extension
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.admin_level = 'support_admin'
ORDER BY sa.created_at DESC;

-- name: UpdateAdminLevel :exec
UPDATE system_admins
SET 
    admin_level = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: PromoteToSuperAdmin :exec
UPDATE system_admins
SET 
    admin_level = 'super_admin',
    can_manage_users = true,
    can_manage_clinics = true,
    can_manage_content = true,
    can_view_analytics = true,
    can_manage_system = true,
    permissions = jsonb_build_object(
        'manage_users', true,
        'manage_clinics', true,
        'manage_content', true,
        'view_analytics', true,
        'manage_system', true
    ),
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- REGIONAL ASSIGNMENT QUERIES
-- ============================================

-- name: UpdateAssignedRegions :exec
UPDATE system_admins
SET 
    assigned_regions = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: AddRegionAssignment :exec
UPDATE system_admins
SET 
    assigned_regions = array_append(assigned_regions, $2),
    updated_at = NOW()
WHERE id = $1 AND NOT ($2 = ANY(assigned_regions));

-- name: RemoveRegionAssignment :exec
UPDATE system_admins
SET 
    assigned_regions = array_remove(assigned_regions, $2),
    updated_at = NOW()
WHERE id = $1;

-- name: GetAdminsByRegion :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    u.phone,
    sa.admin_level,
    sa.department,
    sa.work_phone
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE $1 = ANY(sa.assigned_regions)
ORDER BY sa.admin_level, sa.created_at;

-- name: GetRegionsForAdmin :one
SELECT assigned_regions
FROM system_admins
WHERE id = $1;

-- name: CheckAdminHasRegion :one
SELECT EXISTS(
    SELECT 1 FROM system_admins
    WHERE id = $1 AND $2 = ANY(assigned_regions)
) as has_region;

-- ============================================
-- DEPARTMENT QUERIES
-- ============================================

-- name: GetAdminsByDepartment :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.work_phone,
    sa.extension
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.department = $1
ORDER BY sa.admin_level, sa.created_at;

-- name: UpdateDepartment :exec
UPDATE system_admins
SET 
    department = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetDepartmentList :many
SELECT DISTINCT department
FROM system_admins
WHERE department IS NOT NULL
ORDER BY department;

-- name: CountAdminsByDepartment :many
SELECT 
    department,
    COUNT(*) as admin_count,
    COUNT(*) FILTER (WHERE admin_level = 'super_admin') as super_admin_count,
    COUNT(*) FILTER (WHERE admin_level = 'regional_admin') as regional_admin_count,
    COUNT(*) FILTER (WHERE admin_level = 'support_admin') as support_admin_count
FROM system_admins
WHERE department IS NOT NULL
GROUP BY department
ORDER BY admin_count DESC;

-- ============================================
-- PERMISSION-BASED QUERIES
-- ============================================

-- name: GetAdminsWithUserManagement :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.can_manage_users = true
ORDER BY sa.admin_level, sa.created_at;

-- name: GetAdminsWithClinicManagement :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.assigned_regions
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.can_manage_clinics = true
ORDER BY sa.admin_level, sa.created_at;

-- name: GetAdminsWithContentManagement :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.can_manage_content = true
ORDER BY sa.admin_level, sa.created_at;

-- name: GetAdminsWithAnalyticsAccess :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.can_view_analytics = true
ORDER BY sa.admin_level, sa.created_at;

-- name: GetAdminsWithSystemManagement :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.can_manage_system = true
ORDER BY sa.admin_level, sa.created_at;

-- name: GetAdminsWithPermission :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.permissions
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE 
    (CASE 
        WHEN $1 = 'manage_users' THEN sa.can_manage_users
        WHEN $1 = 'manage_clinics' THEN sa.can_manage_clinics
        WHEN $1 = 'manage_content' THEN sa.can_manage_content
        WHEN $1 = 'view_analytics' THEN sa.can_view_analytics
        WHEN $1 = 'manage_system' THEN sa.can_manage_system
        ELSE false
    END) = true
ORDER BY sa.admin_level, sa.created_at;

-- ============================================
-- CONTACT INFORMATION
-- ============================================

-- name: UpdateContactInfo :exec
UPDATE system_admins
SET 
    work_phone = COALESCE($2, work_phone),
    extension = COALESCE($3, extension),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateWorkPhone :exec
UPDATE system_admins
SET 
    work_phone = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateExtension :exec
UPDATE system_admins
SET 
    extension = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetAdminContactInfo :one
SELECT 
    sa.id,
    u.email,
    u.phone as personal_phone,
    sa.work_phone,
    sa.extension,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.id = $1;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchSystemAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    u.phone,
    sa.admin_level,
    sa.department,
    sa.assigned_regions,
    sa.work_phone
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE 
    ($1::VARCHAR IS NULL OR u.email ILIKE '%' || $1 || '%')
    AND ($2::VARCHAR IS NULL OR sa.admin_level = $2)
    AND ($3::VARCHAR IS NULL OR sa.department = $3)
    AND ($4::VARCHAR IS NULL OR $4 = ANY(sa.assigned_regions))
ORDER BY sa.admin_level, sa.created_at DESC;

-- name: FindAdminByEmail :one
SELECT 
    sa.id,
    sa.user_id,
    sa.admin_level,
    sa.department,
    sa.permissions
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE u.email = $1;

-- name: FindAdminByPhone :one
SELECT 
    sa.id,
    sa.user_id,
    sa.admin_level,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.work_phone = $1 OR u.phone = $1;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountSystemAdmins :one
SELECT 
    COUNT(*) as total_admins,
    COUNT(*) FILTER (WHERE admin_level = 'super_admin') as super_admin_count,
    COUNT(*) FILTER (WHERE admin_level = 'regional_admin') as regional_admin_count,
    COUNT(*) FILTER (WHERE admin_level = 'support_admin') as support_admin_count,
    COUNT(*) FILTER (WHERE can_manage_users = true) as user_managers,
    COUNT(*) FILTER (WHERE can_manage_clinics = true) as clinic_managers,
    COUNT(*) FILTER (WHERE can_view_analytics = true) as analytics_viewers
FROM system_admins;

-- name: GetAdminLevelDistribution :many
SELECT 
    admin_level,
    COUNT(*) as admin_count,
    AVG(array_length(assigned_regions, 1)) FILTER (WHERE assigned_regions IS NOT NULL) as avg_regions_per_admin
FROM system_admins
GROUP BY admin_level
ORDER BY 
    CASE admin_level
        WHEN 'super_admin' THEN 1
        WHEN 'regional_admin' THEN 2
        WHEN 'support_admin' THEN 3
        ELSE 4
    END;

-- name: GetPermissionStatistics :one
SELECT 
    COUNT(*) FILTER (WHERE can_manage_users = true) as with_user_mgmt,
    COUNT(*) FILTER (WHERE can_manage_clinics = true) as with_clinic_mgmt,
    COUNT(*) FILTER (WHERE can_manage_content = true) as with_content_mgmt,
    COUNT(*) FILTER (WHERE can_view_analytics = true) as with_analytics,
    COUNT(*) FILTER (WHERE can_manage_system = true) as with_system_mgmt,
    COUNT(*) FILTER (WHERE 
        can_manage_users = true AND 
        can_manage_clinics = true AND 
        can_manage_content = true AND 
        can_view_analytics = true AND 
        can_manage_system = true
    ) as with_all_permissions
FROM system_admins;

-- name: GetRegionCoverage :many
SELECT 
    unnest(assigned_regions) as region,
    COUNT(*) as admin_count
FROM system_admins
WHERE assigned_regions IS NOT NULL
GROUP BY region
ORDER BY admin_count DESC;

-- ============================================
-- LISTING & PAGINATION
-- ============================================

-- name: ListSystemAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    u.phone,
    sa.admin_level,
    sa.department,
    sa.assigned_regions,
    sa.can_manage_users,
    sa.can_manage_clinics,
    sa.can_view_analytics,
    sa.created_at
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
ORDER BY 
    CASE sa.admin_level
        WHEN 'super_admin' THEN 1
        WHEN 'regional_admin' THEN 2
        WHEN 'support_admin' THEN 3
        ELSE 4
    END,
    sa.created_at DESC
LIMIT $1 OFFSET $2;

-- name: GetAllSystemAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department,
    sa.work_phone
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
ORDER BY sa.admin_level, sa.created_at;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetAdminsByUserIDs :many
SELECT 
    sa.id,
    sa.user_id,
    sa.admin_level,
    sa.department,
    sa.permissions
FROM system_admins sa
WHERE sa.user_id = ANY($1::uuid[])
ORDER BY sa.admin_level;

-- name: BulkUpdatePermissions :exec
UPDATE system_admins
SET 
    permissions = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkAssignRegion :exec
UPDATE system_admins
SET 
    assigned_regions = array_append(assigned_regions, $2),
    updated_at = NOW()
WHERE 
    id = ANY($1::uuid[])
    AND NOT ($2 = ANY(assigned_regions));

-- name: BulkRemoveRegion :exec
UPDATE system_admins
SET 
    assigned_regions = array_remove(assigned_regions, $2),
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkUpdateDepartment :exec
UPDATE system_admins
SET 
    department = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: CheckAdminExists :one
SELECT EXISTS(
    SELECT 1 FROM system_admins
    WHERE user_id = $1
) as exists;

-- name: CheckIsSuperAdmin :one
SELECT EXISTS(
    SELECT 1 FROM system_admins
    WHERE user_id = $1 AND admin_level = 'super_admin'
) as is_super_admin;

-- name: CheckHasPermission :one
SELECT 
    CASE 
        WHEN $2 = 'manage_users' THEN can_manage_users
        WHEN $2 = 'manage_clinics' THEN can_manage_clinics
        WHEN $2 = 'manage_content' THEN can_manage_content
        WHEN $2 = 'view_analytics' THEN can_view_analytics
        WHEN $2 = 'manage_system' THEN can_manage_system
        ELSE false
    END as has_permission
FROM system_admins
WHERE user_id = $1;

-- name: GetAdminPermissions :one
SELECT 
    admin_level,
    permissions,
    can_manage_users,
    can_manage_clinics,
    can_manage_content,
    can_view_analytics,
    can_manage_system,
    assigned_regions
FROM system_admins
WHERE user_id = $1;

-- name: CountAdminsByLevel :one
SELECT COUNT(*) as admin_count
FROM system_admins
WHERE admin_level = $1;

-- ============================================
-- AUDIT & REPORTING
-- ============================================

-- name: GetRecentlyCreatedAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department,
    sa.created_at
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.created_at >= $1
ORDER BY sa.created_at DESC;

-- name: GetRecentlyUpdatedAdmins :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.updated_at
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE sa.updated_at >= $1
ORDER BY sa.updated_at DESC;

-- name: GetAdminsWithoutRegions :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.department
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE 
    sa.admin_level = 'regional_admin'
    AND (sa.assigned_regions IS NULL OR array_length(sa.assigned_regions, 1) = 0)
ORDER BY sa.created_at;

-- name: GetAdminsWithLimitedPermissions :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    sa.permissions
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
WHERE 
    NOT (sa.can_manage_users AND sa.can_manage_clinics AND 
         sa.can_manage_content AND sa.can_view_analytics AND 
         sa.can_manage_system)
ORDER BY sa.admin_level, sa.created_at;

-- name: GetAdminActivitySummary :one
SELECT 
    sa.id,
    sa.admin_level,
    sa.department,
    sa.assigned_regions,
    sa.permissions,
    COUNT(ua.id) as total_activities,
    MAX(ua.performed_at) as last_activity
FROM system_admins sa
LEFT JOIN user_activities ua ON sa.user_id = ua.user_id
WHERE sa.id = $1
GROUP BY sa.id, sa.admin_level, sa.department, sa.assigned_regions, sa.permissions;

-- name: GetAdminsWithNoRecentActivity :many
SELECT 
    sa.id,
    sa.user_id,
    u.email,
    sa.admin_level,
    MAX(ua.performed_at) as last_activity
FROM system_admins sa
JOIN users u ON sa.user_id = u.id
LEFT JOIN user_activities ua ON sa.user_id = ua.user_id
GROUP BY sa.id, sa.user_id, u.email, sa.admin_level
HAVING MAX(ua.performed_at) < $1 OR MAX(ua.performed_at) IS NULL
ORDER BY last_activity ASC NULLS FIRST;
