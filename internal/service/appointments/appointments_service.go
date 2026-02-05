package appointments

import (
	"context"
	"fmt"
	"time"

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

func NewAppointmentService(appointmentRepo repository.AppointmentRepository,
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

func (s *appointmentService) BookAppointment(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error) {
	start := time.Now()

	// Validate that the user exists and has patient role
	user, err := s.userRepo.GetUserByID(ctx, appointment.PatientID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", appointment.PatientID.String()).Msg("Failed to get user")
		return appointments.Appointment{}, domain.NewAppError(err, "User not found", 404)
	}

	if user.Role != "patient" {
		s.logger.Warn().
			Str("user_id", appointment.PatientID.String()).
			Str("role", user.Role).
			Msg("User is not a patient")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "User must be a patient", 400)
	}

	// Validate clinic exists
	clinic, err := s.clinicRepo.GetClinicByID(ctx, appointment.ClinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", appointment.ClinicID.String()).Msg("Failed to get clinic")
		return appointments.Appointment{}, domain.NewAppError(err, "Clinic not found", 404)
	}

	// Validate clinic is active/verified if needed
	if !clinic.IsVerified {
		s.logger.Warn().
			Str("clinic_id", clinic.ID.String()).
			Msg("Clinic is not verified")
		return appointments.Appointment{}, domain.NewAppError(domain.ErrValidation, "Clinic is not verified", 400)
	}

	created, err := s.appointmentRepo.BookAppointment(ctx, appointment)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to book an appointment")
		return appointments.Appointment{}, domain.NewAppError(err, "Failed to book an appointment", 500)
	}

	// Invalidate appointment-related cache
	s.invalidateAppointmentCache(ctx, created)

	// Log success with correct IDs
	s.logger.Info().
		Str("patient_id", created.PatientID.String()).
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
