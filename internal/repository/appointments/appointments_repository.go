package appointments

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	appointmentsDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "appointments_db_query_duration_seconds",
			Help:    "Appointments database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	appointmentsDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "appointments_db_query_total",
			Help: "Total number of appointments database queries",
		},
		[]string{"operation", "status"},
	)
)

type appointmentsRepository struct {
	querier sqlc.Querier
}

func NewAppointmentsRepository(pool *pgxpool.Pool) repository.AppointmentRepository {
	return NewAppointmentsRepositoryWithQuerier(sqlc.New(pool))
}

func NewAppointmentsRepositoryWithQuerier(querier sqlc.Querier) repository.AppointmentRepository {
	return &appointmentsRepository{
		querier: querier,
	}
}

func (r *appointmentsRepository) BookAppointment(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Extract just the time portion (HH:MM:SS) from the appointment time
	appointmentTime := extractTimeOfDay(appointment.AppointmentTime)

	created, err := r.querier.CreateAppointment(ctx, sqlc.CreateAppointmentParams{
		ClinicID:            uuidToPgtypeUUID(appointment.ClinicID),
		PatientID:           uuidToPgtypeUUID(appointment.PatientID),
		AppointmentDate:     pgtype.Date{Time: appointment.AppointmentDate, Valid: true},
		AppointmentTime:     appointmentTime, // Now using proper time-of-day
		AppointmentDatetime: pgtype.Timestamp{Time: appointment.AppointmentDatetime, Valid: true},
		PatientName:         appointment.PatientName,
		PatientPhone:        appointment.PatientPhone,
		PatientEmail:        pgtypeTextFromStringPtr(appointment.PatientEmail),
		ReasonForVisit:      appointment.ReasonForVisit,
		Notes:               pgtypeTextFromStringPtr(appointment.Notes),
		Status:              string(appointments.StatusPending),
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("create_appointment", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "create appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("create_appointment", "success").Inc()
	return r.mapToCreate(created), nil
}

func (r *appointmentsRepository) mapToCreate(row sqlc.Appointment) appointments.Appointment {
	// When reading from DB, combine date and time to create a proper time.Time
	appointmentTime := combineDateAndTime(row.AppointmentDate.Time, row.AppointmentTime)

	return appointments.Appointment{
		ID:                  pgtypeUUIDToUUID(row.ID),
		ClinicID:            pgtypeUUIDToUUID(row.ClinicID),
		PatientID:           pgtypeUUIDToUUID(row.PatientID),
		AppointmentDate:     row.AppointmentDate.Time,
		AppointmentTime:     appointmentTime, // Combined date + time
		AppointmentDatetime: row.AppointmentDatetime.Time,
		PatientName:         row.PatientName,
		PatientPhone:        row.PatientPhone,
		PatientEmail:        pgtypeTextToStringPtr(row.PatientEmail),
		ReasonForVisit:      row.ReasonForVisit,
		Notes:               pgtypeTextToStringPtr(row.Notes),
		Status:              appointments.AppointmentStatus(row.Status),
		CancellationReason:  pgtypeTextToStringPtr(row.CancellationReason),
		CancelledBy:         pgtypeUUIDToUUIDPtr(row.CancelledBy),
		CancelledAt:         pgtypeTimestampToTimePtr(row.CancelledAt),
		ConfirmedBy:         pgtypeUUIDToUUIDPtr(row.ConfirmedBy),
		ConfirmedAt:         pgtypeTimestampToTimePtr(row.ConfirmedAt),
		ReminderPreferences: mapFromJSONB(row.ReminderPreferences),
		ReminderSent:        mapFromJSONB(row.ReminderSent),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func (r *appointmentsRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// Helper functions for type conversion

func pgtypeUUIDToUUIDPtr(pgu pgtype.UUID) *uuid.UUID {
	if !pgu.Valid {
		return nil
	}
	uid := uuid.UUID(pgu.Bytes)
	return &uid
}

// Helper to extract just the time of day (HH:MM:SS) from a time.Time
func extractTimeOfDay(t time.Time) pgtype.Time {
	if t.IsZero() {
		return pgtype.Time{Valid: false}
	}

	// Get hour, minute, second, nanosecond
	hour := t.Hour()
	minute := t.Minute()
	second := t.Second()
	nanosecond := t.Nanosecond()

	// Calculate microseconds since midnight
	microseconds := (int64(hour)*3600 + int64(minute)*60 + int64(second)) * 1_000_000
	microseconds += int64(nanosecond) / 1_000

	return pgtype.Time{
		Microseconds: microseconds,
		Valid:        true,
	}
}

// Helper to combine date and time-of-day into a single time.Time
func combineDateAndTime(date time.Time, timeOfDay pgtype.Time) time.Time {
	if !timeOfDay.Valid || date.IsZero() {
		return time.Time{}
	}

	// Extract hour, minute, second from microseconds since midnight
	microseconds := timeOfDay.Microseconds
	seconds := microseconds / 1_000_000
	microsecondsRemainder := microseconds % 1_000_000

	hour := seconds / 3600
	minute := (seconds % 3600) / 60
	second := seconds % 60
	nanosecond := int(microsecondsRemainder * 1_000)

	// Combine with date
	return time.Date(
		date.Year(),
		date.Month(),
		date.Day(),
		int(hour),
		int(minute),
		int(second),
		nanosecond,
		date.Location(),
	)
}

// Alternative simpler approach if you want to store time as string
func timeToPgtypeTimeSimple(t time.Time) pgtype.Time {
	if t.IsZero() {
		return pgtype.Time{Valid: false}
	}

	// Format as "15:04:05" and parse as pgtype.Time
	timeStr := t.Format("15:04:05")
	var result pgtype.Time
	err := result.Scan(timeStr)
	if err != nil {
		return pgtype.Time{Valid: false}
	}
	return result
}
