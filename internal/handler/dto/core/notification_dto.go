package core

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
)

// NotificationPreferencesResponse represents notification preferences in responses
type NotificationPreferencesResponse struct {
	ID                             uuid.UUID `json:"id"`
	UserID                         uuid.UUID `json:"user_id"`
	SMSEnabled                     bool      `json:"sms_enabled"`
	EmailEnabled                   bool      `json:"email_enabled"`
	PushEnabled                    bool      `json:"push_enabled"`
	WhatsappEnabled                bool      `json:"whatsapp_enabled"`
	AppointmentReminders           bool      `json:"appointment_reminders"`
	AppointmentReminderHoursBefore int       `json:"appointment_reminder_hours_before"`
	HealthTips                     bool      `json:"health_tips"`
	HealthTipsFrequency            string    `json:"health_tips_frequency"`
	MedicationReminders            bool      `json:"medication_reminders"`
	PrescriptionUpdates            bool      `json:"prescription_updates"`
	ClinicUpdates                  bool      `json:"clinic_updates"`
	Newsletter                     bool      `json:"newsletter"`
	EmergencyAlerts                bool      `json:"emergency_alerts"`
	SystemMaintenance              bool      `json:"system_maintenance"`
	NotificationLanguage           string    `json:"notification_language"`
	QuietHoursStart                *string   `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd                  *string   `json:"quiet_hours_end,omitempty"`
	CreatedAt                      time.Time `json:"created_at"`
	UpdatedAt                      time.Time `json:"updated_at"`
}

// NotificationPreferencesRequest represents request to create/update notification preferences
type NotificationPreferencesRequest struct {
	SMSEnabled                     *bool   `json:"sms_enabled,omitempty"`
	EmailEnabled                   *bool   `json:"email_enabled,omitempty"`
	PushEnabled                    *bool   `json:"push_enabled,omitempty"`
	WhatsappEnabled                *bool   `json:"whatsapp_enabled,omitempty"`
	AppointmentReminders           *bool   `json:"appointment_reminders,omitempty"`
	AppointmentReminderHoursBefore *int    `json:"appointment_reminder_hours_before,omitempty"`
	HealthTips                     *bool   `json:"health_tips,omitempty"`
	HealthTipsFrequency            string  `json:"health_tips_frequency,omitempty"`
	MedicationReminders            *bool   `json:"medication_reminders,omitempty"`
	PrescriptionUpdates            *bool   `json:"prescription_updates,omitempty"`
	ClinicUpdates                  *bool   `json:"clinic_updates,omitempty"`
	Newsletter                     *bool   `json:"newsletter,omitempty"`
	EmergencyAlerts                *bool   `json:"emergency_alerts,omitempty"`
	SystemMaintenance              *bool   `json:"system_maintenance,omitempty"`
	NotificationLanguage           string  `json:"notification_language,omitempty"`
	QuietHoursStart                *string `json:"quiet_hours_start,omitempty"`
	QuietHoursEnd                  *string `json:"quiet_hours_end,omitempty"`
}

// UpdateChannelSettingsRequest represents request to update notification channels
type UpdateChannelSettingsRequest struct {
	SMSEnabled   bool `json:"sms_enabled"`
	EmailEnabled bool `json:"email_enabled"`
	PushEnabled  bool `json:"push_enabled"`
}

// UpdateAppointmentRemindersRequest represents request to update appointment reminder settings
type UpdateAppointmentRemindersRequest struct {
	Enabled     bool `json:"enabled"`
	HoursBefore int  `json:"hours_before" validate:"min=1"`
}

// UpdateHealthTipsRequest represents request to update health tips settings
type UpdateHealthTipsRequest struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency" validate:"required,oneof=daily weekly monthly never"`
}

// SetQuietHoursRequest represents request to set quiet hours
type SetQuietHoursRequest struct {
	StartTime *string `json:"start_time,omitempty"` // Format: "HH:MM:SS"
	EndTime   *string `json:"end_time,omitempty"`   // Format: "HH:MM:SS"
}

// CanSendNotificationResponse represents response for can send notification check
type CanSendNotificationResponse struct {
	CanSend          bool      `json:"can_send"`
	UserID           uuid.UUID `json:"user_id"`
	NotificationType string    `json:"notification_type"`
	Channel          string    `json:"channel"`
	Timestamp        time.Time `json:"timestamp"`
}

// UsersWithDisabledNotificationsResponse represents response for users with disabled notifications
type UsersWithDisabledNotificationsResponse struct {
	UserIDs          []string `json:"user_ids"`
	Count            int      `json:"count"`
	NotificationType string   `json:"notification_type"`
}

// ToNotificationPreferencesResponse converts domain.NotificationPreferences to NotificationPreferencesResponse
func ToNotificationPreferencesResponse(prefs core.NotificationPreferences) NotificationPreferencesResponse {
	return NotificationPreferencesResponse{
		ID:                             prefs.ID,
		UserID:                         prefs.UserID,
		SMSEnabled:                     prefs.SMSEnabled,
		EmailEnabled:                   prefs.EmailEnabled,
		PushEnabled:                    prefs.PushEnabled,
		WhatsappEnabled:                prefs.WhatsappEnabled,
		AppointmentReminders:           prefs.AppointmentReminders,
		AppointmentReminderHoursBefore: prefs.AppointmentReminderHoursBefore,
		HealthTips:                     prefs.HealthTips,
		HealthTipsFrequency:            prefs.HealthTipsFrequency,
		MedicationReminders:            prefs.MedicationReminders,
		PrescriptionUpdates:            prefs.PrescriptionUpdates,
		ClinicUpdates:                  prefs.ClinicUpdates,
		Newsletter:                     prefs.Newsletter,
		EmergencyAlerts:                prefs.EmergencyAlerts,
		SystemMaintenance:              prefs.SystemMaintenance,
		NotificationLanguage:           prefs.NotificationLanguage,
		QuietHoursStart:                prefs.QuietHoursStart,
		QuietHoursEnd:                  prefs.QuietHoursEnd,
		CreatedAt:                      prefs.CreatedAt,
		UpdatedAt:                      prefs.UpdatedAt,
	}
}

// ToNotificationPreferences converts NotificationPreferencesRequest to domain.NotificationPreferences
func ToNotificationPreferences(req NotificationPreferencesRequest) core.NotificationPreferences {
	prefs := core.NotificationPreferences{
		NotificationLanguage: req.NotificationLanguage,
		HealthTipsFrequency:  req.HealthTipsFrequency,
		QuietHoursStart:      req.QuietHoursStart,
		QuietHoursEnd:        req.QuietHoursEnd,
	}

	// Handle optional boolean fields
	if req.SMSEnabled != nil {
		prefs.SMSEnabled = *req.SMSEnabled
	}
	if req.EmailEnabled != nil {
		prefs.EmailEnabled = *req.EmailEnabled
	}
	if req.PushEnabled != nil {
		prefs.PushEnabled = *req.PushEnabled
	}
	if req.WhatsappEnabled != nil {
		prefs.WhatsappEnabled = *req.WhatsappEnabled
	}
	if req.AppointmentReminders != nil {
		prefs.AppointmentReminders = *req.AppointmentReminders
	}
	if req.AppointmentReminderHoursBefore != nil {
		prefs.AppointmentReminderHoursBefore = *req.AppointmentReminderHoursBefore
	}
	if req.HealthTips != nil {
		prefs.HealthTips = *req.HealthTips
	}
	if req.MedicationReminders != nil {
		prefs.MedicationReminders = *req.MedicationReminders
	}
	if req.PrescriptionUpdates != nil {
		prefs.PrescriptionUpdates = *req.PrescriptionUpdates
	}
	if req.ClinicUpdates != nil {
		prefs.ClinicUpdates = *req.ClinicUpdates
	}
	if req.Newsletter != nil {
		prefs.Newsletter = *req.Newsletter
	}
	if req.EmergencyAlerts != nil {
		prefs.EmergencyAlerts = *req.EmergencyAlerts
	}
	if req.SystemMaintenance != nil {
		prefs.SystemMaintenance = *req.SystemMaintenance
	}

	return prefs
}
