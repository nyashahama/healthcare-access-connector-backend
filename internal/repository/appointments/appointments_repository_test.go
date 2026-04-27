package appointments

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/appointments"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func uuidPgtypeFromString(s string) pgtype.UUID {
	return pgtype.UUID{Bytes: uuid.MustParse(s), Valid: true}
}

func nowTime() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func stringPtr(s string) *string {
	return &s
}

func pgtypeTimeFromString(t string) pgtype.Time {
	parsed, _ := time.Parse("15:04:05", t)
	hour := parsed.Hour()
	minute := parsed.Minute()
	second := parsed.Second()
	microseconds := (int64(hour)*3600 + int64(minute)*60 + int64(second)) * 1_000_000
	return pgtype.Time{Microseconds: microseconds, Valid: true}
}

func TestAppointmentRepository_BookAppointment(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	appointmentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	clinicID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	patientID := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		appointment  appointments.Appointment
		mockSetup     func(*mocks.MockQuerier)
		expectedApp   appointments.Appointment
		expectError   bool
		errContains  string
	}{
		{
			name: "success",
			appointment: appointments.Appointment{
				ClinicID:            clinicID,
				PatientID:           patientID,
				AppointmentDate:     now,
				AppointmentTime:     now,
				AppointmentDatetime: now,
				PatientName:         "John Doe",
				PatientPhone:        "+1234567890",
				PatientEmail:        stringPtr("john@example.com"),
				ReasonForVisit:      "Checkup",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.Appointment{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ClinicID:            uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					PatientID:           uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
					AppointmentDate:     pgtype.Date{Time: now, Valid: true},
					AppointmentTime:     pgtypeTimeFromString("00:00:00"),
					AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
					PatientName:         "John Doe",
					PatientPhone:        "+1234567890",
					PatientEmail:        pgtype.Text{String: "john@example.com", Valid: true},
					ReasonForVisit:      "Checkup",
					Status:              "pending",
					CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreateAppointment", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectedApp: appointments.Appointment{
				ID:            appointmentID,
				ClinicID:      clinicID,
				PatientID:     patientID,
				PatientName:   "John Doe",
				PatientPhone:  "+1234567890",
				ReasonForVisit: "Checkup",
				Status:        appointments.StatusPending,
			},
			expectError:  false,
			errContains: "",
		},
		{
			name: "database error",
			appointment: appointments.Appointment{
				ClinicID:       clinicID,
				PatientID:      patientID,
				PatientName:    "John Doe",
				PatientPhone:   "+1234567890",
				ReasonForVisit: "Checkup",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, assert.AnError)
			},
			expectError:  true,
			errContains: "",
		},
		{
			name: "scheduling conflict",
			appointment: appointments.Appointment{
				ClinicID:       clinicID,
				PatientID:      patientID,
				PatientName:    "John Doe",
				PatientPhone:   "+1234567890",
				ReasonForVisit: "Checkup",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{
					Code:            "23505",
					ConstraintName: "appointments_clinic_id_appointment_date_appointment_time_key",
				}
				m.On("CreateAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, pgErr)
			},
			expectError:  true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApp, err := repo.BookAppointment(ctx, tt.appointment)

			if tt.expectError {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedApp.PatientName, gotApp.PatientName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_GetAppointmentByID(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	appointmentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedApp   appointments.Appointment
		expectError   bool
		errIsNotFound bool
	}{
		{
			name: "found",
			id:   appointmentID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.Appointment{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ClinicID:            uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					PatientID:           uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
					AppointmentDate:     pgtype.Date{Time: now, Valid: true},
					AppointmentTime:     pgtypeTimeFromString("10:00:00"),
					AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
					PatientName:         "John Doe",
					PatientPhone:        "+1234567890",
					ReasonForVisit:      "Checkup",
					Status:              "pending",
					CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetAppointment", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRow, nil)
			},
			expectedApp: appointments.Appointment{
				ID:            appointmentID,
				PatientName:   "John Doe",
				PatientPhone:  "+1234567890",
				ReasonForVisit: "Checkup",
				Status:        appointments.StatusPending,
			},
			expectError:   false,
			errIsNotFound: false,
		},
		{
			name: "not found",
			id:   appointmentID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointment", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.Appointment{}, pgx.ErrNoRows)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: true,
		},
		{
			name: "database error",
			id:   appointmentID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, assert.AnError)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApp, err := repo.GetAppointmentByID(ctx, tt.id)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
				assert.Equal(t, tt.expectedApp, gotApp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedApp.ID, gotApp.ID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_GetAppointmentsByPatient(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		patientID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedApps  []appointments.Appointment
		expectError   bool
	}{
		{
			name:      "found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRows := []sqlc.Appointment{
					{
						ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						ClinicID:            uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
						PatientID:           uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						AppointmentDate:     pgtype.Date{Time: now, Valid: true},
						AppointmentTime:     pgtypeTimeFromString("10:00:00"),
						AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
						PatientName:         "John Doe",
						PatientPhone:        "+1234567890",
						ReasonForVisit:      "Checkup",
						Status:              "pending",
						CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetAppointmentsByPatient", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRows, nil)
			},
			expectedApps: []appointments.Appointment{
				{
					ID:             uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
					PatientName:   "John Doe",
					PatientPhone:  "+1234567890",
					ReasonForVisit: "Checkup",
					Status:        appointments.StatusPending,
				},
			},
			expectError: false,
		},
		{
			name:      "empty",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentsByPatient", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return([]sqlc.Appointment{}, nil)
			},
			expectedApps: []appointments.Appointment{},
			expectError:  false,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentsByPatient", ctx, mock.Anything).Return([]sqlc.Appointment{}, assert.AnError)
			},
			expectedApps: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApps, err := repo.GetAppointmentsByPatient(ctx, tt.patientID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expectedApps), len(gotApps))
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_GetAppointmentsByClinic(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	clinicID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		clinicID      uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedApps  []appointments.Appointment
		expectError   bool
	}{
		{
			name:     "found",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRows := []sqlc.Appointment{
					{
						ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						ClinicID:            uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						PatientID:           uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
						AppointmentDate:     pgtype.Date{Time: now, Valid: true},
						AppointmentTime:     pgtypeTimeFromString("10:00:00"),
						AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
						PatientName:         "John Doe",
						PatientPhone:        "+1234567890",
						ReasonForVisit:      "Checkup",
						Status:              "pending",
						CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetAppointmentsByClinic", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(expectedRows, nil)
			},
			expectedApps: []appointments.Appointment{
				{
					ID:             uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
					PatientName:   "John Doe",
					PatientPhone:  "+1234567890",
					ReasonForVisit: "Checkup",
					Status:        appointments.StatusPending,
				},
			},
			expectError: false,
		},
		{
			name:     "empty",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentsByClinic", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return([]sqlc.Appointment{}, nil)
			},
			expectedApps: []appointments.Appointment{},
			expectError:  false,
		},
		{
			name:     "database error",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentsByClinic", ctx, mock.Anything).Return([]sqlc.Appointment{}, assert.AnError)
			},
			expectedApps: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApps, err := repo.GetAppointmentsByClinic(ctx, tt.clinicID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expectedApps), len(gotApps))
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_RescheduleAppointment(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	appointmentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		newDate       time.Time
		newTime       time.Time
		newDatetime   time.Time
		mockSetup     func(*mocks.MockQuerier)
		expectedApp   appointments.Appointment
		expectError   bool
		errIsNotFound bool
	}{
		{
			name:        "success",
			id:          appointmentID,
			newDate:     now,
			newTime:     now,
			newDatetime: now,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.Appointment{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ClinicID:            uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					PatientID:           uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
					AppointmentDate:     pgtype.Date{Time: now, Valid: true},
					AppointmentTime:     pgtypeTimeFromString("14:00:00"),
					AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
					PatientName:         "John Doe",
					PatientPhone:        "+1234567890",
					ReasonForVisit:      "Checkup",
					Status:              "pending",
					CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("RescheduleAppointment", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectedApp: appointments.Appointment{
				ID:             appointmentID,
				PatientName:   "John Doe",
				PatientPhone:  "+1234567890",
				ReasonForVisit: "Checkup",
				Status:        appointments.StatusPending,
			},
			expectError:   false,
			errIsNotFound: false,
		},
		{
			name:        "not found",
			id:          appointmentID,
			newDate:     now,
			newTime:     now,
			newDatetime: now,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("RescheduleAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, pgx.ErrNoRows)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: true,
		},
		{
			name:        "database error",
			id:          appointmentID,
			newDate:     now,
			newTime:     now,
			newDatetime: now,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("RescheduleAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, assert.AnError)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApp, err := repo.RescheduleAppointment(ctx, tt.id, tt.newDate, tt.newTime, tt.newDatetime)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
				assert.Equal(t, tt.expectedApp, gotApp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedApp.ID, gotApp.ID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_ConfirmAppointment(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	appointmentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	confirmedBy := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		confirmedBy   uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedApp   appointments.Appointment
		expectError   bool
		errIsNotFound bool
	}{
		{
			name:        "success",
			id:          appointmentID,
			confirmedBy: confirmedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.Appointment{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ClinicID:            uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
					PatientID:           uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
					AppointmentDate:     pgtype.Date{Time: now, Valid: true},
					AppointmentTime:     pgtypeTimeFromString("10:00:00"),
					AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
					PatientName:         "John Doe",
					PatientPhone:        "+1234567890",
					ReasonForVisit:      "Checkup",
					Status:              "confirmed",
					ConfirmedBy:         uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					ConfirmedAt:         pgtype.Timestamp{Time: now, Valid: true},
					CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("ConfirmAppointment", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectedApp: appointments.Appointment{
				ID:            appointmentID,
				PatientName:   "John Doe",
				PatientPhone:  "+1234567890",
				ReasonForVisit: "Checkup",
				Status:        appointments.StatusConfirmed,
				ConfirmedBy:   &confirmedBy,
			},
			expectError:   false,
			errIsNotFound: false,
		},
		{
			name:        "not found",
			id:          appointmentID,
			confirmedBy: confirmedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("ConfirmAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, pgx.ErrNoRows)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: true,
		},
		{
			name:        "database error",
			id:          appointmentID,
			confirmedBy: confirmedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("ConfirmAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, assert.AnError)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApp, err := repo.ConfirmAppointment(ctx, tt.id, tt.confirmedBy)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
				assert.Equal(t, tt.expectedApp, gotApp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedApp.ID, gotApp.ID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_CancelAppointment(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	appointmentID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	cancelledBy := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		reason        string
		cancelledBy   uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedApp   appointments.Appointment
		expectError   bool
		errIsNotFound bool
	}{
		{
			name:        "success",
			id:          appointmentID,
			reason:      "Patient request",
			cancelledBy: cancelledBy,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.Appointment{
					ID:                  uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					ClinicID:            uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
					PatientID:           uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
					AppointmentDate:     pgtype.Date{Time: now, Valid: true},
					AppointmentTime:     pgtypeTimeFromString("10:00:00"),
					AppointmentDatetime: pgtype.Timestamp{Time: now, Valid: true},
					PatientName:         "John Doe",
					PatientPhone:        "+1234567890",
					ReasonForVisit:      "Checkup",
					Status:              "cancelled",
					CancellationReason:  pgtype.Text{String: "Patient request", Valid: true},
					CancelledBy:         uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					CancelledAt:         pgtype.Timestamp{Time: now, Valid: true},
					CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CancelAppointment", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectedApp: appointments.Appointment{
				ID:                appointmentID,
				PatientName:       "John Doe",
				PatientPhone:      "+1234567890",
				ReasonForVisit:    "Checkup",
				Status:            appointments.StatusCancelled,
				CancellationReason: stringPtr("Patient request"),
				CancelledBy:       &cancelledBy,
			},
			expectError:   false,
			errIsNotFound: false,
		},
		{
			name:        "not found",
			id:          appointmentID,
			reason:      "Patient request",
			cancelledBy: cancelledBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CancelAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, pgx.ErrNoRows)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: true,
		},
		{
			name:        "database error",
			id:          appointmentID,
			reason:      "Patient request",
			cancelledBy: cancelledBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CancelAppointment", ctx, mock.Anything).Return(sqlc.Appointment{}, assert.AnError)
			},
			expectedApp:   appointments.Appointment{},
			expectError:   true,
			errIsNotFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotApp, err := repo.CancelAppointment(ctx, tt.id, tt.reason, tt.cancelledBy)

			if tt.expectError {
				require.Error(t, err)
				if tt.errIsNotFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
				assert.Equal(t, tt.expectedApp, gotApp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedApp.ID, gotApp.ID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_CheckSchedulingConflict(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	clinicID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		clinicID      uuid.UUID
		date          time.Time
		appointmentTime time.Time
		mockSetup     func(*mocks.MockQuerier)
		expectedBool  bool
		expectError   bool
	}{
		{
			name:            "conflict",
			clinicID:        clinicID,
			date:            now,
			appointmentTime: now,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.CheckSchedulingConflictRow{
					ID:              uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					PatientName:     "John Doe",
					AppointmentTime: pgtypeTimeFromString("10:00:00"),
				}
				m.On("CheckSchedulingConflict", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectedBool: true,
			expectError:  false,
		},
		{
			name:            "no conflict",
			clinicID:        clinicID,
			date:            now,
			appointmentTime: now,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CheckSchedulingConflict", ctx, mock.Anything).Return(sqlc.CheckSchedulingConflictRow{}, pgx.ErrNoRows)
			},
			expectedBool: false,
			expectError:  false,
		},
		{
			name:            "database error",
			clinicID:        clinicID,
			date:            now,
			appointmentTime: now,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CheckSchedulingConflict", ctx, mock.Anything).Return(sqlc.CheckSchedulingConflictRow{}, assert.AnError)
			},
			expectedBool: false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotBool, err := repo.CheckSchedulingConflict(ctx, tt.clinicID, tt.date, tt.appointmentTime)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBool, gotBool)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAppointmentRepository_GetAppointmentCount(t *testing.T) {
	ctx := context.Background()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		patientID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedCount int64
		expectError   bool
	}{
		{
			name:      "returns count",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentCount", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(int64(5), nil)
			},
			expectedCount: 5,
			expectError:   false,
		},
		{
			name:      "zero",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentCount", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(int64(0), nil)
			},
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAppointmentCount", ctx, mock.Anything).Return(int64(0), assert.AnError)
			},
			expectedCount: 0,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewAppointmentsRepositoryWithQuerier(mockQuerier)

			gotCount, err := repo.GetAppointmentCount(ctx, tt.patientID)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, gotCount)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}