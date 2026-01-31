package admin

import (
	"time"

	"github.com/google/uuid"
)

// SystemAdmin represents a system administrator
type SystemAdmin struct {
	ID              uuid.UUID   `json:"id"`
	UserID          uuid.UUID   `json:"user_id"`
	AdminLevel      string      `json:"admin_level"` // 'super_admin', 'regional_admin', 'support_admin'
	AssignedRegions []string    `json:"assigned_regions,omitempty"`
	Department      *string     `json:"department,omitempty"`
	Permissions     interface{} `json:"permissions"` // JSONB - store as interface{} or map[string]interface{}

	// Permission Flags
	CanManageUsers   bool `json:"can_manage_users"`
	CanManageClinics bool `json:"can_manage_clinics"`
	CanManageContent bool `json:"can_manage_content"`
	CanViewAnalytics bool `json:"can_view_analytics"`
	CanManageSystem  bool `json:"can_manage_system"`

	// Contact Information
	WorkPhone *string `json:"work_phone,omitempty"`
	Extension *string `json:"extension,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AdminContactInfo represents contact information for an admin
type AdminContactInfo struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	WorkPhone *string   `json:"work_phone,omitempty"`
	Extension *string   `json:"extension,omitempty"`
}

// AdminLevelDistribution represents distribution of admins by level
type AdminLevelDistribution struct {
	AdminLevel string `json:"admin_level"`
	Count      int64  `json:"count"`
}

// PermissionStatistics represents statistics about admin permissions
type PermissionStatistics struct {
	TotalAdmins           int64 `json:"total_admins"`
	WithUserManagement    int64 `json:"with_user_management"`
	WithClinicManagement  int64 `json:"with_clinic_management"`
	WithContentManagement int64 `json:"with_content_management"`
	WithAnalyticsAccess   int64 `json:"with_analytics_access"`
	WithSystemManagement  int64 `json:"with_system_management"`
	SuperAdmins           int64 `json:"super_admins"`
	RegionalAdmins        int64 `json:"regional_admins"`
	SupportAdmins         int64 `json:"support_admins"`
}

// RegionCoverage represents admin coverage by region
type RegionCoverage struct {
	Region     string `json:"region"`
	AdminCount int64  `json:"admin_count"`
}

// DepartmentCount represents count of admins by department
type DepartmentCount struct {
	Department *string `json:"department,omitempty"`
	Count      int64   `json:"count"`
}

// AdminActivitySummary represents activity summary for admins
type AdminActivitySummary struct {
	TotalAdmins      int64      `json:"total_admins"`
	RecentlyCreated  int64      `json:"recently_created"`
	RecentlyUpdated  int64      `json:"recently_updated"`
	WithoutRegions   int64      `json:"without_regions"`
	WithLimitedPerms int64      `json:"with_limited_permissions"`
	LastActivityDate *time.Time `json:"last_activity_date,omitempty"`
}

// AdminPermissions represents the permission set for an admin
type AdminPermissions struct {
	ID               uuid.UUID   `json:"id"`
	UserID           uuid.UUID   `json:"user_id"`
	AdminLevel       string      `json:"admin_level"`
	Permissions      interface{} `json:"permissions"`
	CanManageUsers   bool        `json:"can_manage_users"`
	CanManageClinics bool        `json:"can_manage_clinics"`
	CanManageContent bool        `json:"can_manage_content"`
	CanViewAnalytics bool        `json:"can_view_analytics"`
	CanManageSystem  bool        `json:"can_manage_system"`
}
