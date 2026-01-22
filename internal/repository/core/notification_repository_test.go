package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Helper function to assert equality between two core.NotificationPreferences structs
func assertNotificationPreferencesEqual(t *testing.T, expected, got core.NotificationPreferences, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	assert.Equal(t, expected.UserID, got.UserID, msgAndArgs...)
	assert.Equal(t, expected.SMSEnabled, got.SMSEnabled, msgAndArgs...)
	assert.Equal(t, expected.EmailEnabled, got.EmailEnabled, msgAndArgs...)
	assert.Equal(t, expected.PushEnabled, got.PushEnabled, msgAndArgs...)
	assert.Equal(t, expected.WhatsappEnabled, got.WhatsappEnabled, msgAndArgs...)
	assert.Equal(t, expected.AppointmentReminders, got.AppointmentReminders, msgAndArgs...)
	assert.Equal(t, expected.AppointmentReminderHoursBefore, got.AppointmentReminderHoursBefore, msgAndArgs...)
	assert.Equal(t, expected.HealthTips, got.HealthTips, msgAndArgs...)
	assert.Equal(t, expected.HealthTipsFrequency, got.HealthTipsFrequency, msgAndArgs...)
	assert.Equal(t, expected.MedicationReminders, got.MedicationReminders, msgAndArgs...)
	assert.Equal(t, expected.PrescriptionUpdates, got.PrescriptionUpdates, msgAndArgs...)
	assert.Equal(t, expected.ClinicUpdates, got.ClinicUpdates, msgAndArgs...)
	assert.Equal(t, expected.Newsletter, got.Newsletter, msgAndArgs...)
	assert.Equal(t, expected.EmergencyAlerts, got.EmergencyAlerts, msgAndArgs...)
	assert.Equal(t, expected.SystemMaintenance, got.SystemMaintenance, msgAndArgs...)
	assert.Equal(t, expected.NotificationLanguage, got.NotificationLanguage, msgAndArgs...)
	assert.Equal(t, expected.QuietHoursStart, got.QuietHoursStart, msgAndArgs...)
	assert.Equal(t, expected.QuietHoursEnd, got.QuietHoursEnd, msgAndArgs...)
	assert.WithinDuration(t, expected.CreatedAt, got.CreatedAt, time.Second, msgAndArgs...)
	assert.WithinDuration(t, expected.UpdatedAt, got.UpdatedAt, time.Second, msgAndArgs...)
}

func TestNotificationRepository_CreateNotificationPreferences(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name           string
		prefs          core.NotificationPreferences
		mockSetup      func(*mocks.Querier)
		expectedResult core.NotificationPreferences
		expectedError  error
	}{
		{
			name: "successful create notification preferences with all fields",
			prefs: core.NotificationPreferences{
				UserID:               userID,
				SMSEnabled:           true,
				EmailEnabled:         true,
				PushEnabled:          true,
				AppointmentReminders: true,
				HealthTips:           true,
				NotificationLanguage: "en",
			},
			mockSetup: func(m *mocks.Querier) {
				createdRow := sqlc.CreateNotificationPreferencesRow{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreateNotificationPreferences", ctx, mock.MatchedBy(func(p sqlc.CreateNotificationPreferencesParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsEnabled.Bool == true &&
						p.EmailEnabled.Bool == true &&
						p.PushEnabled.Bool == true &&
						p.AppointmentReminders.Bool == true &&
						p.HealthTips.Bool == true &&
						p.NotificationLanguage.String == "en"
				})).Return(createdRow, nil)
			},
			expectedResult: core.NotificationPreferences{
				ID:                             uuid.MustParse("223e4567-e89b-12d3-a456-426614174000"),
				UserID:                         userID,
				SMSEnabled:                     true,
				EmailEnabled:                   true,
				PushEnabled:                    true,
				AppointmentReminders:           true,
				HealthTips:                     true,
				NotificationLanguage:           "en",
				WhatsappEnabled:                false,
				AppointmentReminderHoursBefore: 24,
				HealthTipsFrequency:            "weekly",
				MedicationReminders:            false,
				PrescriptionUpdates:            true,
				ClinicUpdates:                  true,
				Newsletter:                     false,
				EmergencyAlerts:                true,
				SystemMaintenance:              true,
				CreatedAt:                      now,
				UpdatedAt:                      now,
			},
			expectedError: nil,
		},
		{
			name: "successful create notification preferences with minimal fields",
			prefs: core.NotificationPreferences{
				UserID:       userID,
				SMSEnabled:   false,
				EmailEnabled: false,
				PushEnabled:  false,
			},
			mockSetup: func(m *mocks.Querier) {
				createdRow := sqlc.CreateNotificationPreferencesRow{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					CreatedAt: pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreateNotificationPreferences", ctx, mock.MatchedBy(func(p sqlc.CreateNotificationPreferencesParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsEnabled.Bool == false &&
						p.EmailEnabled.Bool == false &&
						p.PushEnabled.Bool == false &&
						p.AppointmentReminders.Bool == false &&
						p.HealthTips.Bool == false &&
						p.NotificationLanguage.String == ""
				})).Return(createdRow, nil)
			},
			expectedResult: core.NotificationPreferences{
				ID:                             uuid.MustParse("223e4567-e89b-12d3-a456-426614174000"),
				UserID:                         userID,
				SMSEnabled:                     false,
				EmailEnabled:                   false,
				PushEnabled:                    false,
				AppointmentReminders:           false,
				HealthTips:                     false,
				NotificationLanguage:           "",
				WhatsappEnabled:                false,
				AppointmentReminderHoursBefore: 24,
				HealthTipsFrequency:            "weekly",
				MedicationReminders:            false,
				PrescriptionUpdates:            true,
				ClinicUpdates:                  true,
				Newsletter:                     false,
				EmergencyAlerts:                true,
				SystemMaintenance:              true,
				CreatedAt:                      now,
				UpdatedAt:                      now,
			},
			expectedError: nil,
		},
		{
			name: "database error",
			prefs: core.NotificationPreferences{
				UserID:     userID,
				SMSEnabled: true,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("CreateNotificationPreferences", ctx, mock.Anything).Return(sqlc.CreateNotificationPreferencesRow{}, assert.AnError)
			},
			expectedResult: core.NotificationPreferences{},
			expectedError:  fmt.Errorf("create notification preferences failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			result, err := repo.CreateNotificationPreferences(ctx, tt.prefs)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assertNotificationPreferencesEqual(t, tt.expectedResult, result)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_GetNotificationPreferences(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	prefsID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name           string
		userID         uuid.UUID
		mockSetup      func(*mocks.Querier)
		expectedResult core.NotificationPreferences
		expectedError  error
	}{
		{
			name:   "successful get notification preferences",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				prefsRow := sqlc.NotificationPreference{
					ID:                             pgtype.UUID{Bytes: prefsID, Valid: true},
					UserID:                         pgtype.UUID{Bytes: userID, Valid: true},
					SmsEnabled:                     pgtype.Bool{Bool: true, Valid: true},
					EmailEnabled:                   pgtype.Bool{Bool: true, Valid: true},
					PushEnabled:                    pgtype.Bool{Bool: true, Valid: true},
					WhatsappEnabled:                pgtype.Bool{Bool: false, Valid: true},
					AppointmentReminders:           pgtype.Bool{Bool: true, Valid: true},
					AppointmentReminderHoursBefore: pgtype.Int4{Int32: 24, Valid: true},
					HealthTips:                     pgtype.Bool{Bool: true, Valid: true},
					HealthTipsFrequency:            pgtype.Text{String: "weekly", Valid: true},
					MedicationReminders:            pgtype.Bool{Bool: true, Valid: true},
					PrescriptionUpdates:            pgtype.Bool{Bool: true, Valid: true},
					ClinicUpdates:                  pgtype.Bool{Bool: true, Valid: true},
					Newsletter:                     pgtype.Bool{Bool: false, Valid: true},
					EmergencyAlerts:                pgtype.Bool{Bool: true, Valid: true},
					SystemMaintenance:              pgtype.Bool{Bool: true, Valid: true},
					NotificationLanguage:           pgtype.Text{String: "en", Valid: true},
					QuietHoursStart:                pgtype.Time{Microseconds: 0, Valid: true},                    // 00:00:00
					QuietHoursEnd:                  pgtype.Time{Microseconds: 8 * 3600 * 1_000_000, Valid: true}, // 08:00:00
					CreatedAt:                      pgtype.Timestamp{Time: now.Add(-30 * 24 * time.Hour), Valid: true},
					UpdatedAt:                      pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetNotificationPreferences", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(prefsRow, nil)
			},
			expectedResult: core.NotificationPreferences{
				ID:                             prefsID,
				UserID:                         userID,
				SMSEnabled:                     true,
				EmailEnabled:                   true,
				PushEnabled:                    true,
				WhatsappEnabled:                false,
				AppointmentReminders:           true,
				AppointmentReminderHoursBefore: 24,
				HealthTips:                     true,
				HealthTipsFrequency:            "weekly",
				MedicationReminders:            true,
				PrescriptionUpdates:            true,
				ClinicUpdates:                  true,
				Newsletter:                     false,
				EmergencyAlerts:                true,
				SystemMaintenance:              true,
				NotificationLanguage:           "en",
				QuietHoursStart:                stringPtr("00:00:00"),
				QuietHoursEnd:                  stringPtr("08:00:00"),
				CreatedAt:                      now.Add(-30 * 24 * time.Hour),
				UpdatedAt:                      now,
			},
			expectedError: nil,
		},
		{
			name:   "preferences not found",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetNotificationPreferences", ctx, mock.Anything).Return(sqlc.NotificationPreference{}, pgx.ErrNoRows)
			},
			expectedResult: core.NotificationPreferences{},
			expectedError:  domain.ErrPreferencesNotFound,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetNotificationPreferences", ctx, mock.Anything).Return(sqlc.NotificationPreference{}, assert.AnError)
			},
			expectedResult: core.NotificationPreferences{},
			expectedError:  fmt.Errorf("get notification preferences failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			result, err := repo.GetNotificationPreferences(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if errors.Is(tt.expectedError, domain.ErrPreferencesNotFound) {
					assert.ErrorIs(t, err, domain.ErrPreferencesNotFound)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
			} else {
				require.NoError(t, err)
				assertNotificationPreferencesEqual(t, tt.expectedResult, result)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateNotificationPreferences(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		prefs         core.NotificationPreferences
		mockSetup     func(*mocks.Querier)
		expectedError string // Change to string to check error message
	}{
		{
			name: "successful update existing notification preferences",
			prefs: core.NotificationPreferences{
				UserID:               userID,
				SMSEnabled:           false,
				EmailEnabled:         true,
				PushEnabled:          true,
				AppointmentReminders: true,
				HealthTips:           false,
				MedicationReminders:  true,
				EmergencyAlerts:      true,
			},
			mockSetup: func(m *mocks.Querier) {
				// First call to GetNotificationPreferences (to check existence)
				existingPrefsRow := sqlc.NotificationPreference{
					ID:                   uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:               uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SmsEnabled:           pgtype.Bool{Bool: true, Valid: true},
					EmailEnabled:         pgtype.Bool{Bool: false, Valid: true},
					PushEnabled:          pgtype.Bool{Bool: true, Valid: true},
					AppointmentReminders: pgtype.Bool{Bool: false, Valid: true},
					HealthTips:           pgtype.Bool{Bool: true, Valid: true},
					MedicationReminders:  pgtype.Bool{Bool: false, Valid: true},
					EmergencyAlerts:      pgtype.Bool{Bool: false, Valid: true},
				}
				m.On("GetNotificationPreferences", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(existingPrefsRow, nil)

				// Call to UpdateNotificationPreferences
				m.On("UpdateNotificationPreferences", ctx, mock.MatchedBy(func(p sqlc.UpdateNotificationPreferencesParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsEnabled.Bool == false && // Changed from true
						p.EmailEnabled.Bool == true && // Changed from false
						p.PushEnabled.Bool == true && // Same
						p.AppointmentReminders.Bool == true && // Changed from false
						p.HealthTips.Bool == false && // Changed from true
						p.MedicationReminders.Bool == true && // Changed from false
						p.EmergencyAlerts.Bool == true // Changed from false
				})).Return(nil)
			},
			expectedError: "",
		},
		{
			name: "successful create new preferences when none exist",
			prefs: core.NotificationPreferences{
				UserID:               userID,
				SMSEnabled:           true,
				EmailEnabled:         true,
				PushEnabled:          true,
				AppointmentReminders: true,
				HealthTips:           true,
			},
			mockSetup: func(m *mocks.Querier) {
				// First call to GetNotificationPreferences returns not found
				m.On("GetNotificationPreferences", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.NotificationPreference{}, pgx.ErrNoRows)

				// Then create new preferences
				createdRow := sqlc.CreateNotificationPreferencesRow{
					ID:        uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:    uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					CreatedAt: pgtype.Timestamp{Time: time.Now(), Valid: true},
				}
				m.On("CreateNotificationPreferences", ctx, mock.Anything).Return(createdRow, nil)
			},
			expectedError: "",
		},
		{
			name: "error getting existing preferences",
			prefs: core.NotificationPreferences{
				UserID: userID,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("GetNotificationPreferences", ctx, mock.Anything).Return(sqlc.NotificationPreference{}, assert.AnError)
			},
			expectedError: "get notification preferences for update failed",
		},
		{
			name: "error updating preferences after successful get",
			prefs: core.NotificationPreferences{
				UserID:     userID,
				SMSEnabled: true,
			},
			mockSetup: func(m *mocks.Querier) {
				existingPrefsRow := sqlc.NotificationPreference{
					ID:         uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:     uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SmsEnabled: pgtype.Bool{Bool: false, Valid: true},
				}
				m.On("GetNotificationPreferences", ctx, mock.Anything).Return(existingPrefsRow, nil)
				m.On("UpdateNotificationPreferences", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: "update notification preferences failed",
		},
		{
			name: "error creating new preferences when none exist",
			prefs: core.NotificationPreferences{
				UserID:               userID,
				SMSEnabled:           true,
				EmailEnabled:         true,
				PushEnabled:          true,
				AppointmentReminders: true,
				HealthTips:           true,
			},
			mockSetup: func(m *mocks.Querier) {
				// First call to GetNotificationPreferences returns not found
				m.On("GetNotificationPreferences", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.NotificationPreference{}, pgx.ErrNoRows)

				// Then create new preferences fails
				m.On("CreateNotificationPreferences", ctx, mock.Anything).Return(sqlc.CreateNotificationPreferencesRow{}, assert.AnError)
			},
			expectedError: "create notification preferences during update failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateNotificationPreferences(ctx, tt.prefs)

			if tt.expectedError != "" {
				require.Error(t, err)
				// Check that the error contains the expected error message
				assert.Contains(t, err.Error(), tt.expectedError)
				// Also check it contains the assert.AnError message
				assert.Contains(t, err.Error(), "assert.AnError")
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_DeleteNotificationPreferences(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful delete notification preferences",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteNotificationPreferences", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteNotificationPreferences", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("delete notification preferences failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.DeleteNotificationPreferences(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateChannelSettings(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		sms           bool
		email         bool
		push          bool
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful update channel settings (all true)",
			userID: userID,
			sms:    true,
			email:  true,
			push:   true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateChannelSettings", ctx, mock.MatchedBy(func(p sqlc.UpdateChannelSettingsParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsEnabled.Bool == true &&
						p.EmailEnabled.Bool == true &&
						p.PushEnabled.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "successful update channel settings (mixed)",
			userID: userID,
			sms:    true,
			email:  false,
			push:   true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateChannelSettings", ctx, mock.MatchedBy(func(p sqlc.UpdateChannelSettingsParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsEnabled.Bool == true &&
						p.EmailEnabled.Bool == false &&
						p.PushEnabled.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: userID,
			sms:    true,
			email:  true,
			push:   true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateChannelSettings", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update channel settings failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateChannelSettings(ctx, tt.userID, tt.sms, tt.email, tt.push)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateAppointmentReminders(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		enabled       bool
		hoursBefore   int
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:        "successful update appointment reminders (enabled with custom hours)",
			userID:      userID,
			enabled:     true,
			hoursBefore: 48,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateAppointmentReminders", ctx, mock.MatchedBy(func(p sqlc.UpdateAppointmentRemindersParams) bool {
					return p.UserID.Bytes == userID &&
						p.AppointmentReminders.Bool == true &&
						p.AppointmentReminderHoursBefore.Int32 == 48
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:        "successful update appointment reminders (disabled)",
			userID:      userID,
			enabled:     false,
			hoursBefore: 24,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateAppointmentReminders", ctx, mock.MatchedBy(func(p sqlc.UpdateAppointmentRemindersParams) bool {
					return p.UserID.Bytes == userID &&
						p.AppointmentReminders.Bool == false &&
						p.AppointmentReminderHoursBefore.Int32 == 24
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:        "database error",
			userID:      userID,
			enabled:     true,
			hoursBefore: 24,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateAppointmentReminders", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update appointment reminders failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateAppointmentReminders(ctx, tt.userID, tt.enabled, tt.hoursBefore)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateHealthTips(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		enabled       bool
		frequency     string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:      "successful update health tips (enabled with daily frequency)",
			userID:    userID,
			enabled:   true,
			frequency: "daily",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateHealthTips", ctx, mock.MatchedBy(func(p sqlc.UpdateHealthTipsParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthTips.Bool == true &&
						p.HealthTipsFrequency.String == "daily"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "successful update health tips (disabled)",
			userID:    userID,
			enabled:   false,
			frequency: "weekly",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateHealthTips", ctx, mock.MatchedBy(func(p sqlc.UpdateHealthTipsParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthTips.Bool == false &&
						p.HealthTipsFrequency.String == "weekly"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "database error",
			userID:    userID,
			enabled:   true,
			frequency: "weekly",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateHealthTips", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update health tips failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateHealthTips(ctx, tt.userID, tt.enabled, tt.frequency)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateMedicationReminders(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		enabled       bool
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful update medication reminders (enabled)",
			userID:  userID,
			enabled: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateMedicationReminders", ctx, mock.MatchedBy(func(p sqlc.UpdateMedicationRemindersParams) bool {
					return p.UserID.Bytes == userID && p.MedicationReminders.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "successful update medication reminders (disabled)",
			userID:  userID,
			enabled: false,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateMedicationReminders", ctx, mock.MatchedBy(func(p sqlc.UpdateMedicationRemindersParams) bool {
					return p.UserID.Bytes == userID && p.MedicationReminders.Bool == false
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			enabled: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateMedicationReminders", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update medication reminders failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateMedicationReminders(ctx, tt.userID, tt.enabled)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateEmergencyAlerts(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		enabled       bool
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful update emergency alerts (enabled)",
			userID:  userID,
			enabled: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateEmergencyAlerts", ctx, mock.MatchedBy(func(p sqlc.UpdateEmergencyAlertsParams) bool {
					return p.UserID.Bytes == userID && p.EmergencyAlerts.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "successful update emergency alerts (disabled)",
			userID:  userID,
			enabled: false,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateEmergencyAlerts", ctx, mock.MatchedBy(func(p sqlc.UpdateEmergencyAlertsParams) bool {
					return p.UserID.Bytes == userID && p.EmergencyAlerts.Bool == false
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			enabled: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateEmergencyAlerts", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update emergency alerts failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateEmergencyAlerts(ctx, tt.userID, tt.enabled)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_SetQuietHours(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	startTime := time.Date(2023, 1, 1, 22, 0, 0, 0, time.UTC) // 22:00:00
	endTime := time.Date(2023, 1, 2, 7, 0, 0, 0, time.UTC)    // 07:00:00

	tests := []struct {
		name          string
		userID        uuid.UUID
		startTime     *time.Time
		endTime       *time.Time
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:      "successful set quiet hours with both times",
			userID:    userID,
			startTime: &startTime,
			endTime:   &endTime,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateQuietHours", ctx, mock.MatchedBy(func(p sqlc.UpdateQuietHoursParams) bool {
					return p.UserID.Bytes == userID &&
						p.QuietHoursStart.Valid &&
						p.QuietHoursEnd.Valid
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "successful set quiet hours with only start time",
			userID:    userID,
			startTime: &startTime,
			endTime:   nil,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateQuietHours", ctx, mock.MatchedBy(func(p sqlc.UpdateQuietHoursParams) bool {
					return p.UserID.Bytes == userID &&
						p.QuietHoursStart.Valid &&
						!p.QuietHoursEnd.Valid
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "successful set quiet hours with only end time",
			userID:    userID,
			startTime: nil,
			endTime:   &endTime,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateQuietHours", ctx, mock.MatchedBy(func(p sqlc.UpdateQuietHoursParams) bool {
					return p.UserID.Bytes == userID &&
						!p.QuietHoursStart.Valid &&
						p.QuietHoursEnd.Valid
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "database error",
			userID:    userID,
			startTime: &startTime,
			endTime:   &endTime,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateQuietHours", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("set quiet hours failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.SetQuietHours(ctx, tt.userID, tt.startTime, tt.endTime)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestNotificationRepository_UpdateNotificationLanguage(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		language      string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:     "successful update notification language",
			userID:   userID,
			language: "fr",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateNotificationLanguage", ctx, mock.MatchedBy(func(p sqlc.UpdateNotificationLanguageParams) bool {
					return p.UserID.Bytes == userID && p.NotificationLanguage.String == "fr"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:     "database error",
			userID:   userID,
			language: "es",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateNotificationLanguage", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update notification language failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &notificationRepository{querier: mockQuerier}

			err := repo.UpdateNotificationLanguage(ctx, tt.userID, tt.language)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
