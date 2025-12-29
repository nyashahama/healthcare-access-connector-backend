package core

import (
	"time"

	"github.com/google/uuid"
)

// NotificationPreferences represents user notification settings
type NotificationPreferences struct {
	ID                             uuid.UUID `json:"id"`
	UserID                         uuid.UUID `json:"user_id"`
	SMSEnabled                     bool      `json:"sms_enabled"`
	EmailEnabled                   bool      `json:"email_enabled"`
	PushEnabled                    bool      `json:"push_enabled"`
	WhatsappEnabled                bool      `json:"whatsapp_enabled"`
	AppointmentReminders           bool      `json:"appointment_reminders"`
	AppointmentReminderHoursBefore int       `json:"appointment_reminder_hours_before"`
	HealthTips                     bool      `json:"health_tips"`
	HealthTipsFrequency            string    `json:"health_tips_frequency"` // daily, weekly, monthly
	MedicationReminders            bool      `json:"medication_reminders"`
	PrescriptionUpdates            bool      `json:"prescription_updates"`
	ClinicUpdates                  bool      `json:"clinic_updates"`
	Newsletter                     bool      `json:"newsletter"`
	EmergencyAlerts                bool      `json:"emergency_alerts"`
	SystemMaintenance              bool      `json:"system_maintenance"`
	NotificationLanguage           string    `json:"notification_language"`
	QuietHoursStart                *string   `json:"quiet_hours_start,omitempty"` // TIME format
	QuietHoursEnd                  *string   `json:"quiet_hours_end,omitempty"`
	CreatedAt                      time.Time `json:"created_at"`
	UpdatedAt                      time.Time `json:"updated_at"`
}