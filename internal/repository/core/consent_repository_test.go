package core

import (
	"context"
	"fmt"
	"net/netip"
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

// Helper function to assert equality between two core.PrivacyConsent structs
func assertPrivacyConsentEqual(t *testing.T, expected, got core.PrivacyConsent, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	assert.Equal(t, expected.UserID, got.UserID, msgAndArgs...)
	assert.Equal(t, expected.HealthDataConsent, got.HealthDataConsent, msgAndArgs...)

	if expected.HealthDataConsentDate == nil {
		assert.Nil(t, got.HealthDataConsentDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.HealthDataConsentDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.HealthDataConsentDate, *got.HealthDataConsentDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.HealthDataConsentVersion, got.HealthDataConsentVersion, msgAndArgs...)
	assert.Equal(t, expected.ResearchConsent, got.ResearchConsent, msgAndArgs...)

	if expected.ResearchConsentDate == nil {
		assert.Nil(t, got.ResearchConsentDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ResearchConsentDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.ResearchConsentDate, *got.ResearchConsentDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.EmergencyAccessConsent, got.EmergencyAccessConsent, msgAndArgs...)

	if expected.EmergencyAccessConsentDate == nil {
		assert.Nil(t, got.EmergencyAccessConsentDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.EmergencyAccessConsentDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.EmergencyAccessConsentDate, *got.EmergencyAccessConsentDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.SMSCommunicationConsent, got.SMSCommunicationConsent, msgAndArgs...)
	assert.Equal(t, expected.EmailCommunicationConsent, got.EmailCommunicationConsent, msgAndArgs...)
	assert.Equal(t, expected.DataSharingConsent, got.DataSharingConsent, msgAndArgs...)
	assert.Equal(t, expected.SpecialCategoriesConsent, got.SpecialCategoriesConsent, msgAndArgs...)
	assert.Equal(t, expected.ConsentWithdrawn, got.ConsentWithdrawn, msgAndArgs...)

	if expected.ConsentWithdrawnDate == nil {
		assert.Nil(t, got.ConsentWithdrawnDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ConsentWithdrawnDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.ConsentWithdrawnDate, *got.ConsentWithdrawnDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.WithdrawalReason, got.WithdrawalReason, msgAndArgs...)
	assert.Equal(t, expected.IPAddress, got.IPAddress, msgAndArgs...)
	assert.Equal(t, expected.UserAgent, got.UserAgent, msgAndArgs...)
	assert.WithinDuration(t, expected.CreatedAt, got.CreatedAt, time.Second, msgAndArgs...)
	assert.WithinDuration(t, expected.UpdatedAt, got.UpdatedAt, time.Second, msgAndArgs...)
}

func TestConsentRepository_CreatePrivacyConsent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	fmt.Print(ipAddr)

	tests := []struct {
		name           string
		consent        core.PrivacyConsent
		mockSetup      func(*mocks.Querier)
		expectedResult core.PrivacyConsent
		expectedError  error
	}{
		{
			name: "successful create privacy consent with all fields",
			consent: core.PrivacyConsent{
				UserID:                    userID,
				HealthDataConsent:         true,
				HealthDataConsentDate:     &now,
				HealthDataConsentVersion:  stringPtr("v1.0"),
				EmergencyAccessConsent:    true,
				SMSCommunicationConsent:   true,
				EmailCommunicationConsent: true,
				IPAddress:                 &ipStr,
				UserAgent:                 stringPtr("Mozilla/5.0"),
			},
			mockSetup: func(m *mocks.Querier) {
				createdRow := sqlc.CreatePrivacyConsentRow{
					ID:                uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:            pgtype.UUID{Bytes: userID, Valid: true},
					HealthDataConsent: pgtype.Bool{Bool: true, Valid: true},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreatePrivacyConsent", ctx, mock.MatchedBy(func(p sqlc.CreatePrivacyConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == true &&
						p.HealthDataConsentDate.Time.Equal(now) &&
						p.HealthDataConsentVersion.String == "v1.0" &&
						p.EmergencyAccessConsent.Bool == true &&
						p.SmsCommunicationConsent.Bool == true &&
						p.EmailCommunicationConsent.Bool == true &&
						p.IpAddress.String() == ipStr &&
						p.UserAgent.String == "Mozilla/5.0"
				})).Return(createdRow, nil)
			},
			expectedResult: core.PrivacyConsent{
				ID:                uuid.MustParse("223e4567-e89b-12d3-a456-426614174000"),
				UserID:            userID,
				HealthDataConsent: true,
				CreatedAt:         now,
			},
			expectedError: nil,
		},
		{
			name: "successful create privacy consent with minimal fields",
			consent: core.PrivacyConsent{
				UserID:            userID,
				HealthDataConsent: false,
			},
			mockSetup: func(m *mocks.Querier) {
				createdRow := sqlc.CreatePrivacyConsentRow{
					ID:                uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:            pgtype.UUID{Bytes: userID, Valid: true},
					HealthDataConsent: pgtype.Bool{Bool: false, Valid: true},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreatePrivacyConsent", ctx, mock.MatchedBy(func(p sqlc.CreatePrivacyConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == false &&
						!p.HealthDataConsentDate.Valid &&
						!p.HealthDataConsentVersion.Valid &&
						p.EmergencyAccessConsent.Bool == false &&
						p.SmsCommunicationConsent.Bool == false &&
						p.EmailCommunicationConsent.Bool == false &&
						p.IpAddress == nil &&
						!p.UserAgent.Valid
				})).Return(createdRow, nil)
			},
			expectedResult: core.PrivacyConsent{
				ID:                uuid.MustParse("223e4567-e89b-12d3-a456-426614174000"),
				UserID:            userID,
				HealthDataConsent: false,
				CreatedAt:         now,
			},
			expectedError: nil,
		},
		{
			name: "database error",
			consent: core.PrivacyConsent{
				UserID:            userID,
				HealthDataConsent: true,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("CreatePrivacyConsent", ctx, mock.Anything).Return(sqlc.CreatePrivacyConsentRow{}, assert.AnError)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  fmt.Errorf("create privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.CreatePrivacyConsent(ctx, tt.consent)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assertPrivacyConsentEqual(t, tt.expectedResult, result)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
