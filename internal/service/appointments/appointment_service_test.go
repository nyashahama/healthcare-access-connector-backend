package appointments

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAppointmentRepository struct {
	bookAppointmentFunc           func(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error)
	getAppointmentByIDFunc       func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error)
	getByPatientFunc              func(ctx context.Context, patientID uuid.UUID) ([]appointments.Appointment, error)
	getByClinicFunc               func(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error)
	getByClinicAndDateFunc        func(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]appointments.Appointment, error)
	getTodayAppointmentsFunc      func(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error)
	getPendingAppointmentsFunc    func(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error)
	getAppointmentCountFunc       func(ctx context.Context, patientID uuid.UUID) (int64, error)
	rescheduleAppointmentFunc     func(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error)
	confirmAppointmentFunc        func(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error)
	updateAppointmentNotesFunc    func(ctx context.Context, id uuid.UUID, notes string) (appointments.Appointment, error)
	completeAppointmentFunc       func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error)
	cancelAppointmentFunc         func(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error)
	updateAppointmentStatusFunc   func(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus) (appointments.Appointment, error)
	deleteAppointmentFunc         func(ctx context.Context, id uuid.UUID) error
	checkSchedulingConflictFunc  func(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error)
}

func (m *mockAppointmentRepository) BookAppointment(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error) {
	if m.bookAppointmentFunc != nil {
		return m.bookAppointmentFunc(ctx, appointment)
	}
	return appointment, nil
}

func (m *mockAppointmentRepository) GetAppointmentByID(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	if m.getAppointmentByIDFunc != nil {
		return m.getAppointmentByIDFunc(ctx, id)
	}
	return appointments.Appointment{}, domain.ErrNotFound
}

func (m *mockAppointmentRepository) GetAppointmentsByPatient(ctx context.Context, patientID uuid.UUID) ([]appointments.Appointment, error) {
	if m.getByPatientFunc != nil {
		return m.getByPatientFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockAppointmentRepository) GetAppointmentsByClinic(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	if m.getByClinicFunc != nil {
		return m.getByClinicFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockAppointmentRepository) GetAppointmentsByClinicAndDate(ctx context.Context, clinicID uuid.UUID, date time.Time) ([]appointments.Appointment, error) {
	if m.getByClinicAndDateFunc != nil {
		return m.getByClinicAndDateFunc(ctx, clinicID, date)
	}
	return nil, nil
}

func (m *mockAppointmentRepository) GetTodayAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	if m.getTodayAppointmentsFunc != nil {
		return m.getTodayAppointmentsFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockAppointmentRepository) GetPendingAppointments(ctx context.Context, clinicID uuid.UUID) ([]appointments.Appointment, error) {
	if m.getPendingAppointmentsFunc != nil {
		return m.getPendingAppointmentsFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockAppointmentRepository) GetAppointmentCount(ctx context.Context, patientID uuid.UUID) (int64, error) {
	if m.getAppointmentCountFunc != nil {
		return m.getAppointmentCountFunc(ctx, patientID)
	}
	return 0, nil
}

func (m *mockAppointmentRepository) RescheduleAppointment(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error) {
	if m.rescheduleAppointmentFunc != nil {
		return m.rescheduleAppointmentFunc(ctx, id, newDate, newTime, newDatetime)
	}
	return appointments.Appointment{}, nil
}

func (m *mockAppointmentRepository) ConfirmAppointment(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error) {
	if m.confirmAppointmentFunc != nil {
		return m.confirmAppointmentFunc(ctx, id, confirmedBy)
	}
	return appointments.Appointment{}, nil
}

func (m *mockAppointmentRepository) UpdateAppointmentNotes(ctx context.Context, id uuid.UUID, notes string) (appointments.Appointment, error) {
	if m.updateAppointmentNotesFunc != nil {
		return m.updateAppointmentNotesFunc(ctx, id, notes)
	}
	return appointments.Appointment{}, nil
}

func (m *mockAppointmentRepository) CompleteAppointment(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
	if m.completeAppointmentFunc != nil {
		return m.completeAppointmentFunc(ctx, id)
	}
	return appointments.Appointment{}, nil
}

func (m *mockAppointmentRepository) CancelAppointment(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error) {
	if m.cancelAppointmentFunc != nil {
		return m.cancelAppointmentFunc(ctx, id, reason, cancelledBy)
	}
	return appointments.Appointment{}, nil
}

func (m *mockAppointmentRepository) UpdateAppointmentStatus(ctx context.Context, id uuid.UUID, status appointments.AppointmentStatus) (appointments.Appointment, error) {
	if m.updateAppointmentStatusFunc != nil {
		return m.updateAppointmentStatusFunc(ctx, id, status)
	}
	return appointments.Appointment{}, nil
}

func (m *mockAppointmentRepository) DeleteAppointment(ctx context.Context, id uuid.UUID) error {
	if m.deleteAppointmentFunc != nil {
		return m.deleteAppointmentFunc(ctx, id)
	}
	return nil
}

func (m *mockAppointmentRepository) CheckSchedulingConflict(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
	if m.checkSchedulingConflictFunc != nil {
		return m.checkSchedulingConflictFunc(ctx, clinicID, date, appointmentTime)
	}
	return false, nil
}

type mockClinicRepository struct {
	getByIDFunc func(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
}

func (m *mockClinicRepository) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return providers.Clinic{}, domain.ErrNotFound
}

func (m *mockClinicRepository) CreateClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
	return providers.Clinic{}, nil
}

func (m *mockClinicRepository) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	return nil
}

func (m *mockClinicRepository) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepository) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepository) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockClinicRepository) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	return nil, nil
}

func (m *mockClinicRepository) GetClinics(ctx context.Context) ([]providers.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepository) GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepository) GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicWithOwner, error) {
	return nil, nil
}

func (m *mockClinicRepository) UpdateClinicOwner(ctx context.Context, clinicID, newOwnerID uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicVerification, error) {
	return nil, nil
}

type mockUserRepositoryForAppointment struct {
	getUserByIDFunc func(ctx context.Context, id uuid.UUID) (core.User, error)
}

func (m *mockUserRepositoryForAppointment) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	if m.getUserByIDFunc != nil {
		return m.getUserByIDFunc(ctx, id)
	}
	return core.User{}, domain.ErrUserNotFound
}

func (m *mockUserRepositoryForAppointment) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) UpdateUser(ctx context.Context, user core.User) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForAppointment) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForAppointment) CountUsers(ctx context.Context, role string) (int64, error) {
	return 0, nil
}

func (m *mockUserRepositoryForAppointment) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	return core.User{}, patients.PatientProfile{}, nil
}

func (m *mockUserRepositoryForAppointment) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForAppointment) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	return nil, nil
}

type mockCacheServiceForAppointment struct{}

func (m *mockCacheServiceForAppointment) Get(ctx context.Context, key string, dest interface{}) error {
	return cache.ErrCacheMiss
}

func (m *mockCacheServiceForAppointment) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return nil
}

func (m *mockCacheServiceForAppointment) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *mockCacheServiceForAppointment) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (m *mockCacheServiceForAppointment) Ping(ctx context.Context) error {
	return nil
}

func (m *mockCacheServiceForAppointment) IsAvailable() bool {
	return true
}

func newAppointmentServiceForTest(t *testing.T) *appointmentService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &appointmentService{
		appointmentRepo: &mockAppointmentRepository{},
		clinicRepo:      &mockClinicRepository{},
		userRepo:        &mockUserRepositoryForAppointment{},
		cache:           &mockCacheServiceForAppointment{},
		logger:           &logger,
	}
}

func newAppointmentServiceWithMocks(t *testing.T) (*appointmentService, *mockAppointmentRepository, *mockClinicRepository, *mockUserRepositoryForAppointment) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockAppointmentRepo := &mockAppointmentRepository{}
	mockClinicRepo := &mockClinicRepository{}
	mockUserRepo := &mockUserRepositoryForAppointment{}

	return &appointmentService{
		appointmentRepo: mockAppointmentRepo,
		clinicRepo:      mockClinicRepo,
		userRepo:        mockUserRepo,
		cache:           &mockCacheServiceForAppointment{},
		logger:           &logger,
	}, mockAppointmentRepo, mockClinicRepo, mockUserRepo
}

func TestAppointmentService_BookAppointment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAppointmentRepo, mockClinicRepo, mockUserRepo := newAppointmentServiceWithMocks(t)

		patientID := uuid.New()
		clinicID := uuid.New()
		appointmentTime := time.Now().Add(24 * time.Hour)

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id, Role: "patient"}, nil
		}

		mockClinicRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{ID: id, IsVerified: true}, nil
		}

		mockAppointmentRepo.checkSchedulingConflictFunc = func(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
			return false, nil
		}

		mockAppointmentRepo.bookAppointmentFunc = func(ctx context.Context, appointment appointments.Appointment) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:                  uuid.New(),
				PatientID:           appointment.PatientID,
				ClinicID:            appointment.ClinicID,
				AppointmentDate:     appointment.AppointmentDate,
				AppointmentTime:     appointment.AppointmentTime,
				AppointmentDatetime: appointment.AppointmentDatetime,
				Status:              appointments.StatusPending,
			}, nil
		}

		appointment := appointments.Appointment{
			PatientID:           patientID,
			ClinicID:            clinicID,
			AppointmentDate:     appointmentTime,
			AppointmentTime:     appointmentTime,
			AppointmentDatetime: appointmentTime,
			ReasonForVisit:      "Checkup",
		}

		result, err := svc.BookAppointment(context.Background(), appointment)
		require.NoError(t, err)
		assert.Equal(t, appointments.StatusPending, result.Status)
		assert.NotNil(t, result.ID)
	})

	t.Run("scheduling conflict", func(t *testing.T) {
		svc, _, mockClinicRepo, mockUserRepo := newAppointmentServiceWithMocks(t)

		patientID := uuid.New()
		clinicID := uuid.New()
		appointmentTime := time.Now().Add(24 * time.Hour)

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id, Role: "patient"}, nil
		}

		mockClinicRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{ID: id, IsVerified: true}, nil
		}

		svc.appointmentRepo = &mockAppointmentRepository{
			checkSchedulingConflictFunc: func(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
				return true, nil
			},
		}

		appointment := appointments.Appointment{
			PatientID:           patientID,
			ClinicID:            clinicID,
			AppointmentDate:     appointmentTime,
			AppointmentTime:     appointmentTime,
			AppointmentDatetime: appointmentTime,
			ReasonForVisit:      "Checkup",
		}

		_, err := svc.BookAppointment(context.Background(), appointment)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already booked")
	})

	t.Run("max appointments per day exceeded", func(t *testing.T) {
		svc, mockAppointmentRepo, mockClinicRepo, mockUserRepo := newAppointmentServiceWithMocks(t)

		patientID := uuid.New()
		clinicID := uuid.New()
		appointmentTime := time.Now().Add(24 * time.Hour)

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id, Role: "patient"}, nil
		}

		mockClinicRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{ID: id, IsVerified: true}, nil
		}

		mockAppointmentRepo.checkSchedulingConflictFunc = func(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
			return true, nil
		}

		appointment := appointments.Appointment{
			PatientID:           patientID,
			ClinicID:            clinicID,
			AppointmentDate:     appointmentTime,
			AppointmentTime:     appointmentTime,
			AppointmentDatetime: appointmentTime,
			ReasonForVisit:      "Checkup",
		}

		_, err := svc.BookAppointment(context.Background(), appointment)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already booked")
	})
}

func TestAppointmentService_CancelAppointment(t *testing.T) {
	t.Run("success within window", func(t *testing.T) {
		svc, mockAppointmentRepo, _, mockUserRepo := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()
		patientID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id, Role: "patient"}, nil
		}

		mockAppointmentRepo.getAppointmentByIDFunc = func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:                  appointmentID,
				PatientID:           patientID,
				Status:              appointments.StatusPending,
				AppointmentDatetime: time.Now().Add(48 * time.Hour),
			}, nil
		}

		mockAppointmentRepo.cancelAppointmentFunc = func(ctx context.Context, id uuid.UUID, reason string, cancelledBy uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:                 id,
				Status:             appointments.StatusCancelled,
				CancellationReason: &reason,
			}, nil
		}

		result, err := svc.CancelAppointment(context.Background(), appointmentID, "Changed plans", patientID)
		require.NoError(t, err)
		assert.Equal(t, appointments.StatusCancelled, result.Status)
	})

	t.Run("error - user not found", func(t *testing.T) {
		svc, _, _, mockUserRepo := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{}, domain.ErrUserNotFound
		}

		_, err := svc.CancelAppointment(context.Background(), appointmentID, "Changed plans", uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "User not found")
	})
}

func TestAppointmentService_ConfirmAppointment(t *testing.T) {
	t.Run("success clinic confirms", func(t *testing.T) {
		svc, mockAppointmentRepo, _, mockUserRepo := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()
		confirmerID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id, Role: "provider_staff"}, nil
		}

		mockAppointmentRepo.getAppointmentByIDFunc = func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:     appointmentID,
				Status: appointments.StatusPending,
			}, nil
		}

		mockAppointmentRepo.confirmAppointmentFunc = func(ctx context.Context, id uuid.UUID, confirmedBy uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:         id,
				Status:     appointments.StatusConfirmed,
				ConfirmedBy: &confirmedBy,
			}, nil
		}

		result, err := svc.ConfirmAppointment(context.Background(), appointmentID, confirmerID)
		require.NoError(t, err)
		assert.Equal(t, appointments.StatusConfirmed, result.Status)
	})

	t.Run("unauthorized non-clinic user tries", func(t *testing.T) {
		svc, _, _, mockUserRepo := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()
		confirmerID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id, Role: "patient"}, nil
		}

		_, err := svc.ConfirmAppointment(context.Background(), appointmentID, confirmerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission")
	})
}

func TestAppointmentService_Reschedule(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAppointmentRepo, _, _ := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()
		newDate := time.Now().Add(48 * time.Hour)
		newTime := newDate
		newDatetime := newDate

		mockAppointmentRepo.getAppointmentByIDFunc = func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:                  appointmentID,
				ClinicID:            uuid.New(),
				Status:              appointments.StatusPending,
				AppointmentDatetime: time.Now().Add(24 * time.Hour),
			}, nil
		}

		mockAppointmentRepo.checkSchedulingConflictFunc = func(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
			return false, nil
		}

		mockAppointmentRepo.rescheduleAppointmentFunc = func(ctx context.Context, id uuid.UUID, newDate time.Time, newTime time.Time, newDatetime time.Time) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:                  id,
				AppointmentDate:     newDate,
				AppointmentTime:     newTime,
				AppointmentDatetime: newDatetime,
			}, nil
		}

		result, err := svc.RescheduleAppointment(context.Background(), appointmentID, newDate, newTime, newDatetime)
		require.NoError(t, err)
		assert.Equal(t, newDate, result.AppointmentDate)
	})

	t.Run("conflict on new slot", func(t *testing.T) {
		svc, mockAppointmentRepo, _, _ := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()
		newDate := time.Now().Add(48 * time.Hour)
		newTime := newDate
		newDatetime := newDate

		mockAppointmentRepo.getAppointmentByIDFunc = func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{
				ID:                  appointmentID,
				ClinicID:            uuid.New(),
				Status:              appointments.StatusPending,
				AppointmentDatetime: time.Now().Add(24 * time.Hour),
			}, nil
		}

		mockAppointmentRepo.checkSchedulingConflictFunc = func(ctx context.Context, clinicID uuid.UUID, date time.Time, appointmentTime time.Time) (bool, error) {
			return true, nil
		}

		_, err := svc.RescheduleAppointment(context.Background(), appointmentID, newDate, newTime, newDatetime)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already booked")
	})

	t.Run("not found", func(t *testing.T) {
		svc, mockAppointmentRepo, _, _ := newAppointmentServiceWithMocks(t)

		appointmentID := uuid.New()
		newDate := time.Now().Add(48 * time.Hour)
		newTime := newDate
		newDatetime := newDate

		mockAppointmentRepo.getAppointmentByIDFunc = func(ctx context.Context, id uuid.UUID) (appointments.Appointment, error) {
			return appointments.Appointment{}, domain.ErrNotFound
		}

		_, err := svc.RescheduleAppointment(context.Background(), appointmentID, newDate, newTime, newDatetime)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

var _ repository.AppointmentRepository = (*mockAppointmentRepository)(nil)
var _ repository.ClinicRepository = (*mockClinicRepository)(nil)
var _ repository.UserRepository = (*mockUserRepositoryForAppointment)(nil)
var _ cache.Service = (*mockCacheServiceForAppointment)(nil)