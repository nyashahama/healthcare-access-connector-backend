package appointments

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type appointmentService struct {
	appointmentRepo repository.AppointmentRepository
	clinicRepo      repository.ClinicRepository
	userRepo        repository.UserRepository
	cache           cache.Service
	logger          *zerolog.Logger
}

func NewAppointmentService(
	appointmentRepo repository.AppointmentRepository,
	clinicRepo repository.ClinicRepository,
	userRepo repository.UserRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.AppointmentService {
	return &appointmentService{
		appointmentRepo: appointmentRepo,
		clinicRepo:      clinicRepo,
		userRepo:        userRepo,
		cache:           cache,
		logger:          logger,
	}
}

// BookAppointment creates a new appointment with validation
func (s *appointmentService) BookAppointment(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error) {
	start := time.Now()

	// Validate that the user exists and has patient role
	// NOTE: patient_id actually references users.id, not a separate patients table
	user, err := s.userRepo.GetUserByID(ctx, appointment.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", appointment.PatientID.String()).Msg("Failed to get user")
		return appointments.Appointment{}, domain.NewAppError(err, "User not found", 404)
	}

	// Verify user has patient role
	if user.Role != "patient" {
		s.logger.Warn().
			Str("user_id", appointment.PatientID.String()).
			Str("role", user.Role).
			Msg("User is not a patient")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "User must have patient role", 400)
	}

	// Validate clinic exists
	clinic, err := s.clinicRepo.GetClinicByID(ctx, appointment.ClinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", appointment.ClinicID.String()).Msg("Failed to get clinic")
		return appointments.Appointment{}, domain.NewAppError(err, "Clinic not found", 404)
	}

	// Validate clinic is active/verified
	if !clinic.IsVerified {
		s.logger.Warn().
			Str("clinic_id", clinic.ID.String()).
			Msg("Clinic is not verified")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "Clinic is not verified", 400)
	}

	// Check for scheduling conflicts
	hasConflict, err := s.appointmentRepo.CheckSchedulingConflict(ctx, appointment.ClinicID, appointment.AppointmentDate, appointment.AppointmentTime)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to check scheduling conflict")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to check scheduling conflict", 500)
	}

	if hasConflict {
		s.logger.Warn().
			Str("clinic_id", appointment.ClinicID.String()).
			Time("appointment_date", appointment.AppointmentDate).
			Time("appointment_time", appointment.AppointmentTime).
			Msg("Scheduling conflict detected")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "This time slot is already booked", 409)
	}

	// Validate appointment is in the future
	if appointment.AppointmentDatetime.Before(time.Now()) {
		s.logger.Warn().
			Time("appointment_datetime", appointment.AppointmentDatetime).
			Msg("Appointment datetime is in the past")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "Appointment must be in the future", 400)
	}

	created, err := s.appointmentRepo.BookAppointment(ctx, appointment)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to book an appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to book an appointment", 500)
	}

	// Invalidate appointment-related cache
	s.invalidateAppointmentCache(ctx, created)

	s.logger.Info().
		Str("user_id", created.PatientID.String()). // PatientID is actually a user.id
		Str("appointment_id", created.ID.String()).
		Str("clinic_id", created.ClinicID.String()).
		Time("appointment_date", created.AppointmentDate).
		Str("appointment_time", created.AppointmentTime.Format("15:04:05")).
		Msg("Appointment booked successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", created.ID.String()).
		Msg("BookAppointment completed")

	return created, nil
}

// GetAppointmentByID retrieves a single appointment by ID
func (s *appointmentService) GetAppointmentByID(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()

	// Try to get from cache
	cacheKey := fmt.Sprintf("appointment:%s", id.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached appointments.Appointment
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("appointment_id", id.String()).Msg("Appointment retrieved from cache")
			return cached, nil
		}
	}

	appointment, err := s.appointmentRepo.GetAppointmentByID(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to get appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Appointment not found", 404)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, appointment, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache appointment")
		}
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("GetAppointmentByID completed")

	return appointment, nil
}

// GetAppointmentsByPatient retrieves all appointments for a patient
func (s *appointmentService) GetAppointmentsByPatient(ctx context.Context, patientID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()

	// Try to get from cache
	cacheKey := fmt.Sprintf("appointments:patient:%s", patientID.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []appointments.Appointment
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient appointments retrieved from cache")
			return cached, nil
		}
	}

	appointmentList, err := s.appointmentRepo.GetAppointmentsByPatient(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get appointments by patient")
		return nil, domain.NewAppError(err, "Failed to get appointments", 500)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, appointmentList, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache patient appointments")
		}
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("patient_id", patientID.String()).
		Int("count", len(appointmentList)).
		Msg("GetAppointmentsByPatient completed")

	return appointmentList, nil
}

// GetAppointmentsByClinic retrieves all upcoming appointments for a clinic
func (s *appointmentService) GetAppointmentsByClinic(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()

	// Try to get from cache
	cacheKey := fmt.Sprintf("appointments:clinic:%s", clinicID.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []appointments.Appointment
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Clinic appointments retrieved from cache")
			return cached, nil
		}
	}

	appointmentList, err := s.appointmentRepo.GetAppointmentsByClinic(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get appointments by clinic")
		return nil, domain.NewAppError(err, "Failed to get appointments", 500)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, appointmentList, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache clinic appointments")
		}
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("clinic_id", clinicID.String()).
		Int("count", len(appointmentList)).
		Msg("GetAppointmentsByClinic completed")

	return appointmentList, nil
}

// GetAppointmentsByClinicAndDate retrieves appointments for a clinic on a specific date
func (s *appointmentService) GetAppointmentsByClinicAndDate(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]appointments.Appointment, error) {
	start := time.Now()

	// Try to get from cache
	cacheKey := fmt.Sprintf("appointments:clinic:%s:date:%s", clinicID.String(), date.Format("2006-01-02"))
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []appointments.Appointment
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().
				Str("clinic_id", clinicID.String()).
				Str("date", date.Format("2006-01-02")).
				Msg("Clinic appointments by date retrieved from cache")
			return cached, nil
		}
	}

	appointmentList, err := s.appointmentRepo.GetAppointmentsByClinicAndDate(ctx, clinicID, date)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("clinic_id", clinicID.String()).
			Time("date", date).
			Msg("Failed to get appointments by clinic and date")
		return nil, domain.NewAppError(err, "Failed to get appointments", 500)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, appointmentList, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache clinic appointments by date")
		}
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("clinic_id", clinicID.String()).
		Time("date", date).
		Int("count", len(appointmentList)).
		Msg("GetAppointmentsByClinicAndDate completed")

	return appointmentList, nil
}

// GetTodayAppointments retrieves today's appointments for a clinic
func (s *appointmentService) GetTodayAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()

	// Try to get from cache
	cacheKey := fmt.Sprintf("appointments:clinic:%s:today", clinicID.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []appointments.Appointment
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Today's appointments retrieved from cache")
			return cached, nil
		}
	}

	appointmentList, err := s.appointmentRepo.GetTodayAppointments(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get today's appointments")
		return nil, domain.NewAppError(err, "Failed to get today's appointments", 500)
	}

	// Cache the result (shorter TTL for today's appointments)
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, appointmentList, 2*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache today's appointments")
		}
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("clinic_id", clinicID.String()).
		Int("count", len(appointmentList)).
		Msg("GetTodayAppointments completed")

	return appointmentList, nil
}

// GetPendingAppointments retrieves all pending appointments for a clinic
func (s *appointmentService) GetPendingAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	start := time.Now()

	appointmentList, err := s.appointmentRepo.GetPendingAppointments(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get pending appointments")
		return nil, domain.NewAppError(err, "Failed to get pending appointments", 500)
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("clinic_id", clinicID.String()).
		Int("count", len(appointmentList)).
		Msg("GetPendingAppointments completed")

	return appointmentList, nil
}

// RescheduleAppointment updates the appointment date and time
func (s *appointmentService) RescheduleAppointment(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error) {
	start := time.Now()

	// Get existing appointment to validate
	existing, err := s.appointmentRepo.GetAppointmentByID(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to get appointment for rescheduling")
		return appointments.Appointment{}, domain.NewAppError(err, "Appointment not found", 404)
	}

	// Validate status allows rescheduling
	if existing.Status != appointments.StatusPending && existing.Status != appointments.StatusConfirmed {
		s.logger.Warn().
			Str("appointment_id", id.String()).
			Str("status", string(existing.Status)).
			Msg("Cannot reschedule appointment with current status")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "Cannot reschedule appointment with current status", 400)
	}

	// Validate new appointment is in the future
	if newDatetime.Before(time.Now()) {
		s.logger.Warn().
			Time("new_datetime", newDatetime).
			Msg("New appointment datetime is in the past")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "New appointment must be in the future", 400)
	}

	// Check for scheduling conflicts
	hasConflict, err := s.appointmentRepo.CheckSchedulingConflict(ctx, existing.ClinicID, newDate, newTime)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to check scheduling conflict")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to check scheduling conflict", 500)
	}

	if hasConflict {
		s.logger.Warn().
			Str("clinic_id", existing.ClinicID.String()).
			Time("new_date", newDate).
			Time("new_time", newTime).
			Msg("Scheduling conflict detected for rescheduling")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "This time slot is already booked", 409)
	}

	rescheduled, err := s.appointmentRepo.RescheduleAppointment(ctx, id, newDate, newTime, newDatetime)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to reschedule appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to reschedule appointment", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, rescheduled)

	s.logger.Info().
		Str("appointment_id", rescheduled.ID.String()).
		Time("old_datetime", existing.AppointmentDatetime).
		Time("new_datetime", rescheduled.AppointmentDatetime).
		Msg("Appointment rescheduled successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("RescheduleAppointment completed")

	return rescheduled, nil
}

// ConfirmAppointment confirms a pending appointment
func (s *appointmentService) ConfirmAppointment(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()

	// Validate confirmer exists and has appropriate role
	confirmer, err := s.userRepo.GetUserByID(ctx, confirmedBy)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", confirmedBy.String()).Msg("Failed to get confirmer")
		return appointments.Appointment{}, domain.NewAppError(err, "User not found", 404)
	}
	if confirmer.Role != "provider_staff" && confirmer.Role != "doctor" {
		s.logger.Warn().
			Str("user_id", confirmedBy.String()).
			Str("role", confirmer.Role).
			Msg("User does not have permission to confirm appointments")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "User does not have permission to confirm appointments", 403)
	}

	// Get the appointment first to check its status
	existing, err := s.appointmentRepo.GetAppointmentByID(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Appointment not found")
		return appointments.Appointment{}, domain.NewAppError(err, "Appointment not found", 404)
	}

	// Check if the appointment is in a confirmable state
	if existing.Status != appointments.StatusPending {
		s.logger.Warn().
			Str("appointment_id", id.String()).
			Str("current_status", string(existing.Status)).
			Msg("Appointment cannot be confirmed - not in pending status")
		return appointments.Appointment{}, domain.NewAppError(
			domain.ErrValidation,
			fmt.Sprintf("Appointment cannot be confirmed. Current status: %s", existing.Status),
			400,
		)
	}

	confirmed, err := s.appointmentRepo.ConfirmAppointment(ctx, id, confirmedBy)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to confirm appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to confirm appointment", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, confirmed)

	s.logger.Info().
		Str("appointment_id", confirmed.ID.String()).
		Str("confirmed_by", confirmedBy.String()).
		Msg("Appointment confirmed successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("ConfirmAppointment completed")

	return confirmed, nil
}

// UpdateAppointmentNotes updates the notes of an appointment
func (s *appointmentService) UpdateAppointmentNotes(ctx context.Context, id uuid.UUID, notes string) (appointments.Appointment, error) {
	start := time.Now()

	updated, err := s.appointmentRepo.UpdateAppointmentNotes(ctx, id, notes)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to update appointment notes")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to update appointment notes", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, updated)

	s.logger.Info().
		Str("appointment_id", updated.ID.String()).
		Msg("Appointment notes updated successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("UpdateAppointmentNotes completed")

	return updated, nil
}

// CompleteAppointment marks an appointment as completed
func (s *appointmentService) CompleteAppointment(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()

	completed, err := s.appointmentRepo.CompleteAppointment(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to complete appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to complete appointment", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, completed)

	s.logger.Info().
		Str("appointment_id", completed.ID.String()).
		Msg("Appointment completed successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("CompleteAppointment completed")

	return completed, nil
}

// CancelAppointment cancels an appointment
func (s *appointmentService) CancelAppointment(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error) {
	start := time.Now()

	// Validate canceller exists
	canceller, err := s.userRepo.GetUserByID(ctx, cancelledBy)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", cancelledBy.String()).Msg("Failed to get canceller")
		return appointments.Appointment{}, domain.NewAppError(err, "User not found", 404)
	}

	// Get existing appointment to verify ownership or permission
	existing, err := s.appointmentRepo.GetAppointmentByID(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to get appointment for cancellation")
		return appointments.Appointment{}, domain.NewAppError(err, "Appointment not found", 404)
	}

	// Check permissions: patient can cancel their own, staff/admin can cancel any
	// NOTE: PatientID is actually user_id from the users table
	if canceller.Role == "patient" && existing.PatientID != cancelledBy {
		s.logger.Warn().
			Str("user_id", cancelledBy.String()).
			Str("appointment_user_id", existing.PatientID.String()).
			Msg("Patient trying to cancel another user's appointment")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "Cannot cancel another user's appointment", 403)
	}

	cancelled, err := s.appointmentRepo.CancelAppointment(ctx, id, reason, cancelledBy)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to cancel appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to cancel appointment", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, cancelled)

	s.logger.Info().
		Str("appointment_id", cancelled.ID.String()).
		Str("cancelled_by", cancelledBy.String()).
		Str("reason", reason).
		Msg("Appointment cancelled successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("CancelAppointment completed")

	return cancelled, nil
}

// UpdateAppointmentStatus updates the status of an appointment
func (s *appointmentService) UpdateAppointmentStatus(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus) (appointments.Appointment, error) {
	start := time.Now()

	// Validate status
	validStatuses := map[appointments.AppointmentStatus]bool{
		appointments.StatusPending:   true,
		appointments.StatusConfirmed: true,
		appointments.StatusCancelled: true,
		appointments.StatusCompleted: true,
		appointments.StatusNoShow:    true,
	}

	if !validStatuses[status] {
		s.logger.Warn().Str("status", string(status)).Msg("Invalid appointment status")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "Invalid appointment status", 400)
	}

	updated, err := s.appointmentRepo.UpdateAppointmentStatus(ctx, id, status)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to update appointment status")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to update appointment status", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, updated)

	s.logger.Info().
		Str("appointment_id", updated.ID.String()).
		Str("new_status", string(status)).
		Msg("Appointment status updated successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("UpdateAppointmentStatus completed")

	return updated, nil
}

// DeleteAppointment permanently deletes a cancelled appointment
func (s *appointmentService) DeleteAppointment(ctx context.Context, id uuid.UUID) error {
	start := time.Now()

	// Get appointment to verify it's cancelled and for cache invalidation
	appointment, err := s.appointmentRepo.GetAppointmentByID(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to get appointment for deletion")
		return domain.NewAppError(err, "Appointment not found", 404)
	}

	if appointment.Status != appointments.StatusCancelled {
		s.logger.Warn().
			Str("appointment_id", id.String()).
			Str("status", string(appointment.Status)).
			Msg("Cannot delete non-cancelled appointment")
		return domain.NewAppError(domain.ErrValidation, "Only cancelled appointments can be deleted", 400)
	}

	err = s.appointmentRepo.DeleteAppointment(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("appointment_id", id.String()).Msg("Failed to delete appointment")
		return domain.NewAppError(err, "Failed to delete appointment", 500)
	}

	// Invalidate cache
	s.invalidateAppointmentCache(ctx, appointment)

	s.logger.Info().
		Str("appointment_id", id.String()).
		Msg("Appointment deleted successfully")

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("appointment_id", id.String()).
		Msg("DeleteAppointment completed")

	return nil
}

// GetAppointmentCount gets the total count of completed appointments for a patient
func (s *appointmentService) GetAppointmentCount(ctx context.Context, patientID uuid.UUID) (int64, error) {
	start := time.Now()

	// Try to get from cache
	cacheKey := fmt.Sprintf("appointments:patient:%s:count", patientID.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached int64
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Appointment count retrieved from cache")
			return cached, nil
		}
	}

	count, err := s.appointmentRepo.GetAppointmentCount(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get appointment count")
		return 0, domain.NewAppError(err, "Failed to get appointment count", 500)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, count, 15*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache appointment count")
		}
	}

	s.logger.Debug().
		Dur("duration_ms", time.Since(start)).
		Str("patient_id", patientID.String()).
		Int64("count", count).
		Msg("GetAppointmentCount completed")

	return count, nil
}

// invalidateAppointmentCache invalidates all relevant cache keys for an appointment
func (s *appointmentService) invalidateAppointmentCache(ctx context.Context, appointment appointments.Appointment) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}

	// Invalidate various appointment cache keys
	cacheKeys := []string{
		// Patient's appointments cache
		fmt.Sprintf("appointments:patient:%s", appointment.PatientID.String()),
		fmt.Sprintf("appointments:patient:%s:upcoming", appointment.PatientID.String()),
		fmt.Sprintf("appointments:patient:%s:count", appointment.PatientID.String()),

		// Clinic's appointments cache
		fmt.Sprintf("appointments:clinic:%s", appointment.ClinicID.String()),
		fmt.Sprintf("appointments:clinic:%s:date:%s", appointment.ClinicID.String(), appointment.AppointmentDate.Format("2006-01-02")),
		fmt.Sprintf("appointments:clinic:%s:today", appointment.ClinicID.String()),

		// General appointment caches
		"appointments:pending",
		"appointments:today",

		// Specific appointment cache
		fmt.Sprintf("appointment:%s", appointment.ID.String()),
	}

	for _, key := range cacheKeys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate appointment cache")
		} else {
			s.logger.Debug().Str("key", key).Msg("Invalidated appointment cache")
		}
	}
}
