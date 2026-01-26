// Package core
package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	notificationDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "notification_db_query_duration_seconds",
			Help:    "Notification database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	notificationDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "notification_db_query_total",
			Help: "Total number of notification database queries",
		},
		[]string{"operation", "status"},
	)
)

type notificationRepository struct {
	querier sqlc.Querier
}

// NewNotificationRepository creates a new notification repository using a pool
func NewNotificationRepository(pool *pgxpool.Pool) repository.NotificationRepository {
	return NewNotificationRepositoryWithQuerier(sqlc.New(pool))
}

// NewNotificationRepositoryWithQuerier creates a new notification repository using a provided querier (for transactions)
func NewNotificationRepositoryWithQuerier(querier sqlc.Querier) repository.NotificationRepository {
	return &notificationRepository{
		querier: querier,
	}
}

func (r *notificationRepository) CreateNotificationPreferences(ctx context.Context, prefs core.NotificationPreferences) (core.NotificationPreferences, error) {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.CreateNotificationPreferences(ctx, sqlc.CreateNotificationPreferencesParams{
		UserID:               uuidToPgtypeUUID(prefs.UserID),
		SmsEnabled:           boolToPgtypeBool(prefs.SMSEnabled),
		EmailEnabled:         boolToPgtypeBool(prefs.EmailEnabled),
		PushEnabled:          boolToPgtypeBool(prefs.PushEnabled),
		AppointmentReminders: boolToPgtypeBool(prefs.AppointmentReminders),
		HealthTips:           boolToPgtypeBool(prefs.HealthTips),
		NotificationLanguage: pgtypeTextFromString(prefs.NotificationLanguage),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("create_notification_preferences", "error").Inc()
		return core.NotificationPreferences{}, r.handleError(err, "create notification preferences")
	}

	notificationDBQueryTotal.WithLabelValues("create_notification_preferences", "success").Inc()

	// Return the created prefs with default values for other fields
	return core.NotificationPreferences{
		ID:                   pgtypeUUIDToUUID(created.ID),
		UserID:               pgtypeUUIDToUUID(created.UserID),
		SMSEnabled:           prefs.SMSEnabled,
		EmailEnabled:         prefs.EmailEnabled,
		PushEnabled:          prefs.PushEnabled,
		AppointmentReminders: prefs.AppointmentReminders,
		HealthTips:           prefs.HealthTips,
		NotificationLanguage: prefs.NotificationLanguage,
		// Set defaults for other fields
		WhatsappEnabled:                false,
		AppointmentReminderHoursBefore: 24,
		HealthTipsFrequency:            "weekly",
		MedicationReminders:            false,
		PrescriptionUpdates:            true,
		ClinicUpdates:                  true,
		Newsletter:                     false,
		EmergencyAlerts:                true,
		SystemMaintenance:              true,
		CreatedAt:                      created.CreatedAt.Time,
		UpdatedAt:                      created.CreatedAt.Time,
	}, nil
}

func (r *notificationRepository) GetNotificationPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error) {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	prefs, err := r.querier.GetNotificationPreferences(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			notificationDBQueryTotal.WithLabelValues("get_notification_preferences", "not_found").Inc()
			return core.NotificationPreferences{}, domain.ErrPreferencesNotFound
		}
		notificationDBQueryTotal.WithLabelValues("get_notification_preferences", "error").Inc()
		return core.NotificationPreferences{}, r.handleError(err, "get notification preferences")
	}

	notificationDBQueryTotal.WithLabelValues("get_notification_preferences", "success").Inc()
	return r.mapToNotificationPreferences(prefs), nil
}

func (r *notificationRepository) UpdateNotificationPreferences(ctx context.Context, prefs core.NotificationPreferences) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// First check if preferences exist
	existingPrefs, err := r.GetNotificationPreferences(ctx, prefs.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrPreferencesNotFound) {
			// Create new preferences if they don't exist
			_, err = r.CreateNotificationPreferences(ctx, prefs)
			if err != nil {
				notificationDBQueryTotal.WithLabelValues("update_notification_preferences", "error").Inc()
				return r.handleError(err, "create notification preferences during update")
			}
			notificationDBQueryTotal.WithLabelValues("update_notification_preferences", "success").Inc()
			return nil
		}
		notificationDBQueryTotal.WithLabelValues("update_notification_preferences", "error").Inc()
		return r.handleError(err, "get notification preferences for update")
	}

	// Merge existing preferences with updates
	mergedPrefs := r.mergeNotificationPreferences(existingPrefs, prefs)

	err = r.querier.UpdateNotificationPreferences(ctx, sqlc.UpdateNotificationPreferencesParams{
		UserID:               uuidToPgtypeUUID(mergedPrefs.UserID),
		SmsEnabled:           boolToPgtypeBool(mergedPrefs.SMSEnabled),
		EmailEnabled:         boolToPgtypeBool(mergedPrefs.EmailEnabled),
		PushEnabled:          boolToPgtypeBool(mergedPrefs.PushEnabled),
		AppointmentReminders: boolToPgtypeBool(mergedPrefs.AppointmentReminders),
		HealthTips:           boolToPgtypeBool(mergedPrefs.HealthTips),
		MedicationReminders:  boolToPgtypeBool(mergedPrefs.MedicationReminders),
		EmergencyAlerts:      boolToPgtypeBool(mergedPrefs.EmergencyAlerts),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_notification_preferences", "error").Inc()
		return r.handleError(err, "update notification preferences")
	}

	notificationDBQueryTotal.WithLabelValues("update_notification_preferences", "success").Inc()
	return nil
}

func (r *notificationRepository) DeleteNotificationPreferences(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteNotificationPreferences(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("delete_notification_preferences", "error").Inc()
		return r.handleError(err, "delete notification preferences")
	}

	notificationDBQueryTotal.WithLabelValues("delete_notification_preferences", "success").Inc()
	return nil
}

func (r *notificationRepository) UpdateChannelSettings(ctx context.Context, userID uuid.UUID, sms, email, push bool) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateChannelSettings(ctx, sqlc.UpdateChannelSettingsParams{
		UserID:       uuidToPgtypeUUID(userID),
		SmsEnabled:   boolToPgtypeBool(sms),
		EmailEnabled: boolToPgtypeBool(email),
		PushEnabled:  boolToPgtypeBool(push),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_channel_settings", "error").Inc()
		return r.handleError(err, "update channel settings")
	}

	notificationDBQueryTotal.WithLabelValues("update_channel_settings", "success").Inc()
	return nil
}

func (r *notificationRepository) UpdateAppointmentReminders(ctx context.Context, userID uuid.UUID, enabled bool, hoursBefore int) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateAppointmentReminders(ctx, sqlc.UpdateAppointmentRemindersParams{
		UserID:                         uuidToPgtypeUUID(userID),
		AppointmentReminders:           boolToPgtypeBool(enabled),
		AppointmentReminderHoursBefore: intToPgtypeInt4(hoursBefore),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_appointment_reminders", "error").Inc()
		return r.handleError(err, "update appointment reminders")
	}

	notificationDBQueryTotal.WithLabelValues("update_appointment_reminders", "success").Inc()
	return nil
}

func (r *notificationRepository) UpdateHealthTips(ctx context.Context, userID uuid.UUID, enabled bool, frequency string) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateHealthTips(ctx, sqlc.UpdateHealthTipsParams{
		UserID:              uuidToPgtypeUUID(userID),
		HealthTips:          boolToPgtypeBool(enabled),
		HealthTipsFrequency: pgtypeTextFromString(frequency),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_health_tips", "error").Inc()
		return r.handleError(err, "update health tips")
	}

	notificationDBQueryTotal.WithLabelValues("update_health_tips", "success").Inc()
	return nil
}

func (r *notificationRepository) UpdateMedicationReminders(ctx context.Context, userID uuid.UUID, enabled bool) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateMedicationReminders(ctx, sqlc.UpdateMedicationRemindersParams{
		UserID:              uuidToPgtypeUUID(userID),
		MedicationReminders: boolToPgtypeBool(enabled),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_medication_reminders", "error").Inc()
		return r.handleError(err, "update medication reminders")
	}

	notificationDBQueryTotal.WithLabelValues("update_medication_reminders", "success").Inc()
	return nil
}

func (r *notificationRepository) UpdateEmergencyAlerts(ctx context.Context, userID uuid.UUID, enabled bool) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateEmergencyAlerts(ctx, sqlc.UpdateEmergencyAlertsParams{
		UserID:          uuidToPgtypeUUID(userID),
		EmergencyAlerts: boolToPgtypeBool(enabled),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_emergency_alerts", "error").Inc()
		return r.handleError(err, "update emergency alerts")
	}

	notificationDBQueryTotal.WithLabelValues("update_emergency_alerts", "success").Inc()
	return nil
}

func (r *notificationRepository) SetQuietHours(ctx context.Context, userID uuid.UUID, startTime, endTime *time.Time) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var startPgType, endPgType pgtype.Time
	if startTime != nil {
		startPgType = timePtrToPgtypeTime(startTime)
	}
	if endTime != nil {
		endPgType = timePtrToPgtypeTime(endTime)
	}

	err := r.querier.UpdateQuietHours(ctx, sqlc.UpdateQuietHoursParams{
		UserID:          uuidToPgtypeUUID(userID),
		QuietHoursStart: startPgType,
		QuietHoursEnd:   endPgType,
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("set_quiet_hours", "error").Inc()
		return r.handleError(err, "set quiet hours")
	}

	notificationDBQueryTotal.WithLabelValues("set_quiet_hours", "success").Inc()
	return nil
}

func (r *notificationRepository) UpdateNotificationLanguage(ctx context.Context, userID uuid.UUID, language string) error {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateNotificationLanguage(ctx, sqlc.UpdateNotificationLanguageParams{
		UserID:               uuidToPgtypeUUID(userID),
		NotificationLanguage: pgtypeTextFromString(language),
	})
	if err != nil {
		notificationDBQueryTotal.WithLabelValues("update_notification_language", "error").Inc()
		return r.handleError(err, "update notification language")
	}

	notificationDBQueryTotal.WithLabelValues("update_notification_language", "success").Inc()
	return nil
}

func (r *notificationRepository) GetUsersWithDisabledNotifications(ctx context.Context, notificationType string) ([]uuid.UUID, error) {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetUsersWithDisabledType(ctx, pgtypeTextFromString(notificationType))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			notificationDBQueryTotal.WithLabelValues("get_users_with_disabled_notifications", "not_found").Inc()
			return []uuid.UUID{}, nil
		}
		notificationDBQueryTotal.WithLabelValues("get_users_with_disabled_notifications", "error").Inc()
		return nil, r.handleError(err, "get users with disabled notifications")
	}

	userIDs := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		userIDs = append(userIDs, pgtypeUUIDToUUID(row))
	}

	notificationDBQueryTotal.WithLabelValues("get_users_with_disabled_notifications", "success").Inc()
	return userIDs, nil
}

func (r *notificationRepository) GetUsersForHealthTips(ctx context.Context, frequency string) ([]uuid.UUID, error) {
	start := time.Now()
	defer func() {
		notificationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetUsersForHealthTips(ctx, pgtypeTextFromString(frequency))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			notificationDBQueryTotal.WithLabelValues("get_users_for_health_tips", "not_found").Inc()
			return []uuid.UUID{}, nil
		}
		notificationDBQueryTotal.WithLabelValues("get_users_for_health_tips", "error").Inc()
		return nil, r.handleError(err, "get users for health tips")
	}

	userIDs := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		userIDs = append(userIDs, pgtypeUUIDToUUID(row))
	}

	notificationDBQueryTotal.WithLabelValues("get_users_for_health_tips", "success").Inc()
	return userIDs, nil
}

// handleError converts database errors to domain errors
func (r *notificationRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("duplicate notification preferences for user: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// Helper mapping function
func (r *notificationRepository) mapToNotificationPreferences(row sqlc.NotificationPreference) core.NotificationPreferences {
	return core.NotificationPreferences{
		ID:                             pgtypeUUIDToUUID(row.ID),
		UserID:                         pgtypeUUIDToUUID(row.UserID),
		SMSEnabled:                     pgtypeBoolToBool(row.SmsEnabled),
		EmailEnabled:                   pgtypeBoolToBool(row.EmailEnabled),
		PushEnabled:                    pgtypeBoolToBool(row.PushEnabled),
		WhatsappEnabled:                pgtypeBoolToBool(row.WhatsappEnabled),
		AppointmentReminders:           pgtypeBoolToBool(row.AppointmentReminders),
		AppointmentReminderHoursBefore: pgtypeInt4ToInt(row.AppointmentReminderHoursBefore),
		HealthTips:                     pgtypeBoolToBool(row.HealthTips),
		HealthTipsFrequency:            pgtypeTextToString(row.HealthTipsFrequency),
		MedicationReminders:            pgtypeBoolToBool(row.MedicationReminders),
		PrescriptionUpdates:            pgtypeBoolToBool(row.PrescriptionUpdates),
		ClinicUpdates:                  pgtypeBoolToBool(row.ClinicUpdates),
		Newsletter:                     pgtypeBoolToBool(row.Newsletter),
		EmergencyAlerts:                pgtypeBoolToBool(row.EmergencyAlerts),
		SystemMaintenance:              pgtypeBoolToBool(row.SystemMaintenance),
		NotificationLanguage:           pgtypeTextToString(row.NotificationLanguage),
		QuietHoursStart:                pgtypeTimeToStringPtr(row.QuietHoursStart),
		QuietHoursEnd:                  pgtypeTimeToStringPtr(row.QuietHoursEnd),
		CreatedAt:                      row.CreatedAt.Time,
		UpdatedAt:                      row.UpdatedAt.Time,
	}
}

// Helper function to merge notification preferences
func (r *notificationRepository) mergeNotificationPreferences(existing, updates core.NotificationPreferences) core.NotificationPreferences {
	merged := existing

	if updates.SMSEnabled != existing.SMSEnabled {
		merged.SMSEnabled = updates.SMSEnabled
	}
	if updates.EmailEnabled != existing.EmailEnabled {
		merged.EmailEnabled = updates.EmailEnabled
	}
	if updates.PushEnabled != existing.PushEnabled {
		merged.PushEnabled = updates.PushEnabled
	}
	if updates.WhatsappEnabled != existing.WhatsappEnabled {
		merged.WhatsappEnabled = updates.WhatsappEnabled
	}
	if updates.AppointmentReminders != existing.AppointmentReminders {
		merged.AppointmentReminders = updates.AppointmentReminders
	}
	if updates.AppointmentReminderHoursBefore != existing.AppointmentReminderHoursBefore {
		merged.AppointmentReminderHoursBefore = updates.AppointmentReminderHoursBefore
	}
	if updates.HealthTips != existing.HealthTips {
		merged.HealthTips = updates.HealthTips
	}
	if updates.HealthTipsFrequency != existing.HealthTipsFrequency {
		merged.HealthTipsFrequency = updates.HealthTipsFrequency
	}
	if updates.MedicationReminders != existing.MedicationReminders {
		merged.MedicationReminders = updates.MedicationReminders
	}
	if updates.PrescriptionUpdates != existing.PrescriptionUpdates {
		merged.PrescriptionUpdates = updates.PrescriptionUpdates
	}
	if updates.ClinicUpdates != existing.ClinicUpdates {
		merged.ClinicUpdates = updates.ClinicUpdates
	}
	if updates.Newsletter != existing.Newsletter {
		merged.Newsletter = updates.Newsletter
	}
	if updates.EmergencyAlerts != existing.EmergencyAlerts {
		merged.EmergencyAlerts = updates.EmergencyAlerts
	}
	if updates.SystemMaintenance != existing.SystemMaintenance {
		merged.SystemMaintenance = updates.SystemMaintenance
	}
	if updates.NotificationLanguage != existing.NotificationLanguage {
		merged.NotificationLanguage = updates.NotificationLanguage
	}
	if updates.QuietHoursStart != nil && *updates.QuietHoursStart != "" {
		merged.QuietHoursStart = updates.QuietHoursStart
	}
	if updates.QuietHoursEnd != nil && *updates.QuietHoursEnd != "" {
		merged.QuietHoursEnd = updates.QuietHoursEnd
	}

	return merged
}
