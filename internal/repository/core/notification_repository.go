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
