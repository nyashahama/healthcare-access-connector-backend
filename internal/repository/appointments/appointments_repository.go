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

// BookAppointment creates a new appointment
// NOTE: patient_id in the Appointment struct references users.id from the users table,
// not a separate patients table. The service layer validates the user has role='patient'.
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
		AppointmentTime:     appointmentTime,
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
	return r.mapToAppointment(created), nil
}

// GetAppointmentByID retrieves a single appointment by ID
func (r *appointmentsRepository) GetAppointmentByID(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetAppointment(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_appointment", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "get appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_appointment", "success").Inc()
	return r.mapToAppointment(row), nil
}

// GetAppointmentsByPatient retrieves all appointments for a patient
func (r *appointmentsRepository) GetAppointmentsByPatient(ctx context.Context, patientID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAppointmentsByPatient(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_appointments_by_patient", "error").Inc()
		return nil, r.handleError(err, "get appointments by patient")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_appointments_by_patient", "success").Inc()
	return r.mapToAppointments(rows), nil
}

// GetAppointmentsByClinic retrieves all upcoming appointments for a clinic
func (r *appointmentsRepository) GetAppointmentsByClinic(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAppointmentsByClinic(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_appointments_by_clinic", "error").Inc()
		return nil, r.handleError(err, "get appointments by clinic")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_appointments_by_clinic", "success").Inc()
	return r.mapToAppointments(rows), nil
}

// GetAppointmentsByClinicAndDate retrieves appointments for a clinic on a specific date
func (r *appointmentsRepository) GetAppointmentsByClinicAndDate(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAppointmentsByClinicAndDate(ctx, sqlc.GetAppointmentsByClinicAndDateParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		AppointmentDate: pgtype.Date{Time: date, Valid: true},
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_appointments_by_clinic_and_date", "error").Inc()
		return nil, r.handleError(err, "get appointments by clinic and date")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_appointments_by_clinic_and_date", "success").Inc()
	return r.mapToAppointments(rows), nil
}

// GetTodayAppointments retrieves today's appointments for a clinic
func (r *appointmentsRepository) GetTodayAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetTodayAppointments(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_today_appointments", "error").Inc()
		return nil, r.handleError(err, "get today appointments")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_today_appointments", "success").Inc()
	return r.mapToAppointments(rows), nil
}

// GetPendingAppointments retrieves all pending appointments for a clinic
func (r *appointmentsRepository) GetPendingAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPendingAppointments(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_pending_appointments", "error").Inc()
		return nil, r.handleError(err, "get pending appointments")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_pending_appointments", "success").Inc()
	return r.mapToAppointments(rows), nil
}

// RescheduleAppointment updates the appointment date and time
func (r *appointmentsRepository) RescheduleAppointment(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	appointmentTime := extractTimeOfDay(newTime)

	row, err := r.querier.RescheduleAppointment(ctx, sqlc.RescheduleAppointmentParams{
		ID:                  uuidToPgtypeUUID(id),
		AppointmentDate:     pgtype.Date{Time: newDate, Valid: true},
		AppointmentTime:     appointmentTime,
		AppointmentDatetime: pgtype.Timestamp{Time: newDatetime, Valid: true},
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("reschedule_appointment", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "reschedule appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("reschedule_appointment", "success").Inc()
	return r.mapToAppointment(row), nil
}

// ConfirmAppointment confirms a pending appointment
func (r *appointmentsRepository) ConfirmAppointment(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.ConfirmAppointment(ctx, sqlc.ConfirmAppointmentParams{
		ID:          uuidToPgtypeUUID(id),
		ConfirmedBy: uuidToPgtypeUUID(confirmedBy),
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("confirm_appointment", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "confirm appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("confirm_appointment", "success").Inc()
	return r.mapToAppointment(row), nil
}

// UpdateAppointmentNotes updates the notes of an appointment
func (r *appointmentsRepository) UpdateAppointmentNotes(ctx context.Context, id uuid.UUID, notes string) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.UpdateAppointmentNotes(ctx, sqlc.UpdateAppointmentNotesParams{
		ID:    uuidToPgtypeUUID(id),
		Notes: pgtypeTextFromString(notes),
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("update_appointment_notes", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "update appointment notes")
	}

	appointmentsDBQueryTotal.WithLabelValues("update_appointment_notes", "success").Inc()
	return r.mapToAppointment(row), nil
}

// CompleteAppointment marks an appointment as completed
func (r *appointmentsRepository) CompleteAppointment(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.CompleteAppointment(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("complete_appointment", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "complete appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("complete_appointment", "success").Inc()
	return r.mapToAppointment(row), nil
}

// CancelAppointment cancels an appointment
func (r *appointmentsRepository) CancelAppointment(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.CancelAppointment(ctx, sqlc.CancelAppointmentParams{
		ID:                 uuidToPgtypeUUID(id),
		CancellationReason: pgtypeTextFromString(reason),
		CancelledBy:        uuidToPgtypeUUID(cancelledBy),
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("cancel_appointment", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "cancel appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("cancel_appointment", "success").Inc()
	return r.mapToAppointment(row), nil
}

// UpdateAppointmentStatus updates the status of an appointment
func (r *appointmentsRepository) UpdateAppointmentStatus(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus) (appointments.Appointment, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.UpdateAppointmentStatus(ctx, sqlc.UpdateAppointmentStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: string(status),
	})
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("update_appointment_status", "error").Inc()
		return appointments.Appointment{}, r.handleError(err, "update appointment status")
	}

	appointmentsDBQueryTotal.WithLabelValues("update_appointment_status", "success").Inc()
	return r.mapToAppointment(row), nil
}

// DeleteAppointment permanently deletes a cancelled appointment
func (r *appointmentsRepository) DeleteAppointment(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteAppointment(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("delete_appointment", "error").Inc()
		return r.handleError(err, "delete appointment")
	}

	appointmentsDBQueryTotal.WithLabelValues("delete_appointment", "success").Inc()
	return nil
}

// CheckSchedulingConflict checks if there's a scheduling conflict
func (r *appointmentsRepository) CheckSchedulingConflict(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	timeOfDay := extractTimeOfDay(appointmentTime)

	row, err := r.querier.CheckSchedulingConflict(ctx, sqlc.CheckSchedulingConflictParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		AppointmentDate: pgtype.Date{Time: date, Valid: true},
		AppointmentTime: timeOfDay,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			// No conflict found
			appointmentsDBQueryTotal.WithLabelValues("check_scheduling_conflict", "success").Inc()
			return false, nil
		}
		appointmentsDBQueryTotal.WithLabelValues("check_scheduling_conflict", "error").Inc()
		return false, r.handleError(err, "check scheduling conflict")
	}

	// Conflict found
	appointmentsDBQueryTotal.WithLabelValues("check_scheduling_conflict", "conflict").Inc()
	return row.ID.Valid, nil
}

// GetAppointmentCount gets the total count of completed appointments for a patient
func (r *appointmentsRepository) GetAppointmentCount(ctx context.Context, patientID uuid.UUID) (int64, error) {
	start := time.Now()
	defer func() {
		appointmentsDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.querier.GetAppointmentCount(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		appointmentsDBQueryTotal.WithLabelValues("get_appointment_count", "error").Inc()
		return 0, r.handleError(err, "get appointment count")
	}

	appointmentsDBQueryTotal.WithLabelValues("get_appointment_count", "success").Inc()
	return count, nil
}

// Helper methods

func (r *appointmentsRepository) mapToAppointment(row sqlc.Appointment) appointments.Appointment {
	// When reading from DB, combine date and time to create a proper time.Time
	appointmentTime := combineDateAndTime(row.AppointmentDate.Time, row.AppointmentTime)

	return appointments.Appointment{
		ID:                  pgtypeUUIDToUUID(row.ID),
		ClinicID:            pgtypeUUIDToUUID(row.ClinicID),
		PatientID:           pgtypeUUIDToUUID(row.PatientID),
		AppointmentDate:     row.AppointmentDate.Time,
		AppointmentTime:     appointmentTime,
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

func (r *appointmentsRepository) mapToAppointments(rows []sqlc.Appointment) []appointments.Appointment {
	result := make([]appointments.Appointment, len(rows))
	for i, row := range rows {
		result[i] = r.mapToAppointment(row)
	}
	return result
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
