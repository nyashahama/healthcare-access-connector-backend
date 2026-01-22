package core

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
)

// UserActivityResponse represents user activity data in responses
type UserActivityResponse struct {
	ID              uuid.UUID      `json:"id"`
	UserID          *uuid.UUID     `json:"user_id,omitempty"`
	ActivityType    string         `json:"activity_type"`
	ActivityDetails map[string]any `json:"activity_details,omitempty"`
	IPAddress       *string        `json:"ip_address,omitempty"`
	UserAgent       *string        `json:"user_agent,omitempty"`
	DeviceType      *string        `json:"device_type,omitempty"`
	DeviceID        *string        `json:"device_id,omitempty"`
	Location        map[string]any `json:"location,omitempty"`
	ResourceType    *string        `json:"resource_type,omitempty"`
	ResourceID      *uuid.UUID     `json:"resource_id,omitempty"`
	PerformedAt     time.Time      `json:"performed_at"`
}

// DataAccessLogResponse represents data access log in responses
type DataAccessLogResponse struct {
	ID                   uuid.UUID      `json:"id"`
	AccessedByUserID     *uuid.UUID     `json:"accessed_by_user_id,omitempty"`
	AccessedByRole       *string        `json:"accessed_by_role,omitempty"`
	AccessedUserID       uuid.UUID      `json:"accessed_user_id"`
	AccessedResourceType *string        `json:"accessed_resource_type,omitempty"`
	AccessedResourceID   *uuid.UUID     `json:"accessed_resource_id,omitempty"`
	AccessType           string         `json:"access_type"`
	AccessReason         *string        `json:"access_reason,omitempty"`
	IsEmergencyAccess    bool           `json:"is_emergency_access"`
	IPAddress            *string        `json:"ip_address,omitempty"`
	UserAgent            *string        `json:"user_agent,omitempty"`
	Location             map[string]any `json:"location,omitempty"`
	AccessedAt           time.Time      `json:"accessed_at"`
}

// LogUserActivityRequest represents request to log user activity
type LogUserActivityRequest struct {
	UserID          *uuid.UUID     `json:"user_id,omitempty"`
	ActivityType    string         `json:"activity_type" validate:"required"`
	ActivityDetails map[string]any `json:"activity_details,omitempty"`
	IPAddress       *string        `json:"ip_address,omitempty"`
	UserAgent       *string        `json:"user_agent,omitempty"`
	DeviceType      *string        `json:"device_type,omitempty"`
	DeviceID        *string        `json:"device_id,omitempty"`
	Location        map[string]any `json:"location,omitempty"`
	ResourceType    *string        `json:"resource_type,omitempty"`
	ResourceID      *uuid.UUID     `json:"resource_id,omitempty"`
}

// LogDataAccessRequest represents request to log data access
type LogDataAccessRequest struct {
	AccessedByUserID     *uuid.UUID     `json:"accessed_by_user_id,omitempty"`
	AccessedByRole       *string        `json:"accessed_by_role,omitempty"`
	AccessedUserID       uuid.UUID      `json:"accessed_user_id" validate:"required"`
	AccessedResourceType *string        `json:"accessed_resource_type,omitempty"`
	AccessedResourceID   *uuid.UUID     `json:"accessed_resource_id,omitempty"`
	AccessType           string         `json:"access_type" validate:"required"`
	AccessReason         *string        `json:"access_reason,omitempty"`
	IsEmergencyAccess    bool           `json:"is_emergency_access"`
	IPAddress            *string        `json:"ip_address,omitempty"`
	UserAgent            *string        `json:"user_agent,omitempty"`
	Location             map[string]any `json:"location,omitempty"`
}

// AuditReportRequest represents request parameters for generating reports
type AuditReportRequest struct {
	StartDate time.Time `json:"start_date" validate:"required"`
	EndDate   time.Time `json:"end_date" validate:"required"`
}

// UserActivitiesListResponse represents paginated list of user activities
type UserActivitiesListResponse struct {
	Activities []UserActivityResponse `json:"activities"`
	Count      int                    `json:"count"`
	Limit      int                    `json:"limit"`
	Offset     int                    `json:"offset"`
	UserID     uuid.UUID              `json:"user_id,omitempty"`
}

// DataAccessLogsListResponse represents paginated list of data access logs
type DataAccessLogsListResponse struct {
	AccessLogs []DataAccessLogResponse `json:"access_logs"`
	Count      int                     `json:"count"`
	Limit      int                     `json:"limit"`
	Offset     int                     `json:"offset"`
	UserID     *uuid.UUID              `json:"user_id,omitempty"`
}

// ActivityReportResponse represents activity report data
type ActivityReportResponse struct {
	Report    interface{} `json:"report"`
	StartDate time.Time   `json:"start_date"`
	EndDate   time.Time   `json:"end_date"`
	UserID    *uuid.UUID  `json:"user_id,omitempty"`
}

// SuspiciousActivitiesResponse represents suspicious activities data
type SuspiciousActivitiesResponse struct {
	Activities []UserActivityResponse `json:"suspicious_activities"`
	Count      int                    `json:"count"`
	Threshold  int                    `json:"threshold"`
}

// FailedLoginAttemptsResponse represents failed login attempts data
type FailedLoginAttemptsResponse struct {
	Attempts    []UserActivityResponse `json:"failed_login_attempts"`
	Count       int                    `json:"count"`
	WithinHours float64                `json:"within_hours"`
	UserID      *uuid.UUID             `json:"user_id,omitempty"`
}

// ToUserActivityResponse converts domain.UserActivity to UserActivityResponse
func ToUserActivityResponse(activity core.UserActivity) UserActivityResponse {
	return UserActivityResponse{
		ID:              activity.ID,
		UserID:          activity.UserID,
		ActivityType:    activity.ActivityType,
		ActivityDetails: activity.ActivityDetails,
		IPAddress:       activity.IPAddress,
		UserAgent:       activity.UserAgent,
		DeviceType:      activity.DeviceType,
		DeviceID:        activity.DeviceID,
		Location:        activity.Location,
		ResourceType:    activity.ResourceType,
		ResourceID:      activity.ResourceID,
		PerformedAt:     activity.PerformedAt,
	}
}

// ToDataAccessLogResponse converts domain.DataAccessLog to DataAccessLogResponse
func ToDataAccessLogResponse(log core.DataAccessLog) DataAccessLogResponse {
	return DataAccessLogResponse{
		ID:                   log.ID,
		AccessedByUserID:     log.AccessedByUserID,
		AccessedByRole:       log.AccessedByRole,
		AccessedUserID:       log.AccessedUserID,
		AccessedResourceType: log.AccessedResourceType,
		AccessedResourceID:   log.AccessedResourceID,
		AccessType:           log.AccessType,
		AccessReason:         log.AccessReason,
		IsEmergencyAccess:    log.IsEmergencyAccess,
		IPAddress:            log.IPAddress,
		UserAgent:            log.UserAgent,
		Location:             log.Location,
		AccessedAt:           log.AccessedAt,
	}
}

// FromLogUserActivityRequest converts request to domain.UserActivity
func FromLogUserActivityRequest(req LogUserActivityRequest) core.UserActivity {
	return core.UserActivity{
		UserID:          req.UserID,
		ActivityType:    req.ActivityType,
		ActivityDetails: req.ActivityDetails,
		IPAddress:       req.IPAddress,
		UserAgent:       req.UserAgent,
		DeviceType:      req.DeviceType,
		DeviceID:        req.DeviceID,
		Location:        req.Location,
		ResourceType:    req.ResourceType,
		ResourceID:      req.ResourceID,
		PerformedAt:     time.Now(),
	}
}

// FromLogDataAccessRequest converts request to domain.DataAccessLog
func FromLogDataAccessRequest(req LogDataAccessRequest) core.DataAccessLog {
	return core.DataAccessLog{
		AccessedByUserID:     req.AccessedByUserID,
		AccessedByRole:       req.AccessedByRole,
		AccessedUserID:       req.AccessedUserID,
		AccessedResourceType: req.AccessedResourceType,
		AccessedResourceID:   req.AccessedResourceID,
		AccessType:           req.AccessType,
		AccessReason:         req.AccessReason,
		IsEmergencyAccess:    req.IsEmergencyAccess,
		IPAddress:            req.IPAddress,
		UserAgent:            req.UserAgent,
		Location:             req.Location,
		AccessedAt:           time.Now(),
	}
}
