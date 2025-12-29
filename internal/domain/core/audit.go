package core

import (
	"time"

	"github.com/google/uuid"
)

// UserActivity represents user activity tracking
type UserActivity struct {
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

// DataAccessLog represents data access audit log for POPIA compliance
type DataAccessLog struct {
	ID                   uuid.UUID      `json:"id"`
	AccessedByUserID     *uuid.UUID     `json:"accessed_by_user_id,omitempty"`
	AccessedByRole       *string        `json:"accessed_by_role,omitempty"`
	AccessedUserID       uuid.UUID      `json:"accessed_user_id"`
	AccessedResourceType *string        `json:"accessed_resource_type,omitempty"`
	AccessedResourceID   *uuid.UUID     `json:"accessed_resource_id,omitempty"`
	AccessType           string         `json:"access_type"` // view, edit, export, delete
	AccessReason         *string        `json:"access_reason,omitempty"`
	IsEmergencyAccess    bool           `json:"is_emergency_access"`
	IPAddress            *string        `json:"ip_address,omitempty"`
	UserAgent            *string        `json:"user_agent,omitempty"`
	Location             map[string]any `json:"location,omitempty"`
	AccessedAt           time.Time      `json:"accessed_at"`
}