package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
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
